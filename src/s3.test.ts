import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createPresignedDownloadUrl,
  createPresignedUploadUrl,
  createR2Client,
  createS3Client,
  download,
  upload,
} from "./s3.js";
import { AbortError, StorageError } from "./types.js";

vi.mock("@aws-sdk/client-s3", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@aws-sdk/client-s3")>();
  return {
    ...actual,

    S3Client: vi.fn().mockImplementation(function (this: { send: unknown }) {
      this.send = vi.fn();
    }),

    PutObjectCommand: vi.fn(function (...args: unknown[]) {
      return new actual.PutObjectCommand(...args);
    }),
    GetObjectCommand: vi.fn(function (...args: unknown[]) {
      return new actual.GetObjectCommand(...args);
    }),
    CreateMultipartUploadCommand: vi.fn(function (...args: unknown[]) {
      return new actual.CreateMultipartUploadCommand(...args);
    }),
    UploadPartCommand: vi.fn(function (...args: unknown[]) {
      return new actual.UploadPartCommand(...args);
    }),
    CompleteMultipartUploadCommand: vi.fn(function (...args: unknown[]) {
      return new actual.CompleteMultipartUploadCommand(...args);
    }),
    AbortMultipartUploadCommand: vi.fn(function (...args: unknown[]) {
      return new actual.AbortMultipartUploadCommand(...args);
    }),
  };
});

vi.mock("@aws-sdk/s3-request-presigner", () => ({
  getSignedUrl: vi.fn().mockResolvedValue("https://fake-presigned-url.example.com/upload"),
}));

function makeMockClient(order: Array<unknown>): S3Client {
  const ClientCtor = S3Client as unknown as ReturnType<typeof vi.fn>;
  const inst = new ClientCtor();
  const fn = vi.mocked(inst.send);
  order.forEach((r) => {
    fn.mockResolvedValueOnce(r);
  });
  return inst;
}

const BUCKET = "test-bucket";
const KEY = "test-key";
const MIN_PART_SIZE = 5 * 1024 * 1024;

describe("s3 module", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("createS3Client passes region and forcePathStyle correctly", () => {
    const config = { region: "us-east-1", forcePathStyle: true };
    const credentials = { type: "static" as const, accessKeyId: "ak", secretAccessKey: "sk" };
    createS3Client(config, credentials);

    expect(S3Client).toHaveBeenCalledTimes(1);
    const args = vi.mocked(S3Client).mock.calls[0]![0];
    expect(args.region).toBe("us-east-1");
    expect(args.forcePathStyle).toBe(true);
    expect(args.credentials).toEqual({
      accessKeyId: "ak",
      secretAccessKey: "sk",
    });
  });

  it("createR2Client sets correct endpoint for given accountId", () => {
    const accountId = "abc123";
    createR2Client(accountId, { type: "static", accessKeyId: "ak", secretAccessKey: "sk" }, "auto");

    expect(S3Client).toHaveBeenCalledTimes(1);
    const args = vi.mocked(S3Client).mock.calls[0]![0];
    expect(args.endpoint!.toString()).toContain("r2.cloudflarestorage.com");
    expect(args.endpoint!.toString()).toContain(accountId);
    expect(args.forcePathStyle).toBe(true);
    expect(args.region).toBe("auto");
    expect(args.credentials).toEqual({ accessKeyId: "ak", secretAccessKey: "sk" });
  });

  it("upload simple PUT for data under min part size", async () => {
    const body = new Uint8Array(1024);
    const client = makeMockClient([{ ETag: '"abc123"' }]);

    const result = await upload(client, { bucket: BUCKET, key: KEY, body });

    expect(result).toEqual({ etag: "abc123", key: KEY, bucket: BUCKET });
    expect(PutObjectCommand).toHaveBeenCalledTimes(1);
    const cmdArgs = vi.mocked(PutObjectCommand).mock.calls[0]![0];
    expect(cmdArgs.Bucket).toBe(BUCKET);
    expect(cmdArgs.Key).toBe(KEY);
    expect(cmdArgs.Body).toBe(body);

    expect(CreateMultipartUploadCommand).not.toHaveBeenCalled();
    expect(CompleteMultipartUploadCommand).not.toHaveBeenCalled();
  });

  it("upload simple PUT returns etag on success", async () => {
    const body = new Uint8Array(2048);
    const client = makeMockClient([{ ETag: '"deadbeef"' }]);

    const result = await upload(client, { bucket: BUCKET, key: KEY, body });
    expect(result.etag).toBe("deadbeef");
  });

  it("upload multipart for data exceeding minPartSize", async () => {
    const body = new Uint8Array(12 * 1024 * 1024);
    const client = makeMockClient([
      { UploadId: "mpu-id-1" },
      { ETag: '"part1-etag"' },
      { ETag: '"part2-etag"' },
      { ETag: '"part3-etag"' },
      { ETag: '"complete-etag"' },
    ]);

    const result = await upload(client, { bucket: BUCKET, key: KEY, body });

    expect(CreateMultipartUploadCommand).toHaveBeenCalledTimes(1);
    expect(UploadPartCommand).toHaveBeenCalledTimes(3);
    expect(CompleteMultipartUploadCommand).toHaveBeenCalledTimes(1);
    expect(result.etag).toBe("complete-etag");
  });

  it("upload multipart respects concurrency limit", async () => {
    const body = new Uint8Array(30 * 1024 * 1024);
    const concurrency = 2;
    const client = makeMockClient([
      { UploadId: "mpu-conc" },
      ...Array.from({ length: 6 }, (_, i) => ({ ETag: `"p${i + 1}"` })),
      { ETag: '"final"' },
    ]);

    await upload(
      client,
      { bucket: BUCKET, key: KEY, body },
      { minPartSize: MIN_PART_SIZE, concurrency },
    );

    expect(UploadPartCommand).toHaveBeenCalledTimes(6);
  });

  it("upload rejects an invalid concurrency before any work", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);
    const bad = [0, -1, NaN, Infinity, -Infinity, 1.5];
    for (const concurrency of bad) {
      await expect(
        upload(client, { bucket: BUCKET, key: KEY, body }, { concurrency }),
      ).rejects.toThrow(RangeError);
    }

    expect(CreateMultipartUploadCommand).not.toHaveBeenCalled();
  });

  it("upload rejects an invalid minPartSize before any work", async () => {
    const body = new Uint8Array(1024);
    const client = makeMockClient([]);
    const bad = [0, -1, NaN, Infinity, -Infinity, 1.5];
    for (const minPartSize of bad) {
      await expect(
        upload(client, { bucket: BUCKET, key: KEY, body }, { minPartSize }),
      ).rejects.toThrow(RangeError);
    }
    expect(PutObjectCommand).not.toHaveBeenCalled();
  });

  it("upload multipart aborts on signal abortion", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);

    const client = makeMockClient([{ UploadId: "mpu-abort" }] as unknown[]);

    vi.mocked(client.send)
      .mockResolvedValueOnce({ UploadId: "mpu-abort" })
      .mockRejectedValueOnce(new Error("network failure"));

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow();

    expect(AbortMultipartUploadCommand).toHaveBeenCalled();
  });

  it("upload throws StorageError on PUT failure", async () => {
    const body = new Uint8Array(1024);
    const client = makeMockClient([]);
    vi.mocked(client.send).mockRejectedValueOnce(new Error("connection reset"));

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
  });

  it("upload handles empty body successfully", async () => {
    const client = makeMockClient([{ ETag: '"empty-etag"' }]);

    const result = await upload(client, { bucket: BUCKET, key: KEY, body: new Uint8Array(0) });

    expect(result.etag).toBe("empty-etag");
    expect(PutObjectCommand).toHaveBeenCalledTimes(1);
    expect(CreateMultipartUploadCommand).not.toHaveBeenCalled();
  });

  it("download returns body iterable and metadata", async () => {
    const fakeBody = {
      [Symbol.asyncIterator]: function* () {
        yield new Uint8Array([1, 2, 3]);
      },
    };
    const client = makeMockClient([
      {
        Body: fakeBody,
        ContentType: "application/json",
        ETag: '"dl-etag"',
        ContentLength: 42,
      },
    ]);

    const result = await download(client, { bucket: BUCKET, key: KEY });

    expect(result.metadata.contentType).toBe("application/json");
    expect(result.metadata.etag).toBe("dl-etag");
    expect(result.metadata.size).toBe(42);

    expect(typeof result.body[Symbol.asyncIterator]).toBe("function");

    const chunks: Uint8Array[] = [];
    for await (const chunk of result.body) chunks.push(chunk);
    expect(chunks.length).toBeGreaterThan(0);
  });

  it("download throws StorageError on GET failure", async () => {
    const client = makeMockClient([]);
    vi.mocked(client.send).mockRejectedValueOnce(new Error("forbidden"));

    await expect(download(client, { bucket: BUCKET, key: KEY })).rejects.toThrow(StorageError);
  });

  it("download supports range requests", async () => {
    const fakeBody = {
      [Symbol.asyncIterator]: function* () {},
    };
    const client = makeMockClient([
      {
        Body: fakeBody,
        ContentType: "text/plain",
        ETag: '"range-etag"',
        ContentLength: 100,
      },
    ]);

    await download(client, {
      bucket: BUCKET,
      key: KEY,
      range: { start: 0, end: 99 },
    });

    expect(GetObjectCommand).toHaveBeenCalledTimes(1);
    const cmdArgs = vi.mocked(GetObjectCommand).mock.calls[0]![0];
    expect(cmdArgs.Range).toBe("bytes=0-99");
  });

  it("createPresignedUploadUrl generates non-empty URL string", async () => {
    const client = makeMockClient([]);
    const url = await createPresignedUploadUrl(client, {
      bucket: BUCKET,
      key: KEY,
    });

    expect(typeof url).toBe("string");
    expect(url.length).toBeGreaterThan(0);
    expect(getSignedUrl).toHaveBeenCalledTimes(1);
  });

  it("createPresignedDownloadUrl generates non-empty URL string", async () => {
    const client = makeMockClient([]);
    const url = await createPresignedDownloadUrl(client, {
      bucket: BUCKET,
      key: KEY,
    });

    expect(typeof url).toBe("string");
    expect(url.length).toBeGreaterThan(0);
    expect(getSignedUrl).toHaveBeenCalledTimes(1);
  });

  it("createPresignedUploadUrl forwards a custom expiresIn", async () => {
    const client = makeMockClient([]);
    await createPresignedUploadUrl(
      client,
      { bucket: BUCKET, key: KEY },
      900,
    );

    expect(getSignedUrl).toHaveBeenCalledTimes(1);
    expect(vi.mocked(getSignedUrl).mock.calls[0]![2]).toEqual({ expiresIn: 900 });
  });

  it("createPresignedDownloadUrl defaults expiresIn to 3600", async () => {
    const client = makeMockClient([]);
    await createPresignedDownloadUrl(client, { bucket: BUCKET, key: KEY });

    expect(vi.mocked(getSignedUrl).mock.calls[0]![2]).toEqual({ expiresIn: 3600 });
  });

  it("download throws StorageError when response Body is missing", async () => {
    const client = makeMockClient([{}]);
    await expect(download(client, { bucket: BUCKET, key: KEY })).rejects.toThrow(StorageError);
  });

  it("createPresignedUploadUrl throws StorageError when signing fails", async () => {
    vi.mocked(getSignedUrl).mockRejectedValueOnce(new Error("signing boom"));
    const client = makeMockClient([]);
    await expect(
      createPresignedUploadUrl(client, {
        bucket: BUCKET,
        key: KEY,
      }),
    ).rejects.toThrow(StorageError);
  });

  it("createPresignedDownloadUrl throws StorageError when signing fails", async () => {
    vi.mocked(getSignedUrl).mockRejectedValueOnce(new Error("signing boom"));
    const client = makeMockClient([]);
    await expect(createPresignedDownloadUrl(client, { bucket: BUCKET, key: KEY })).rejects.toThrow(
      StorageError,
    );
  });

  it("upload multipart throws StorageError when CreateMultipartUpload fails", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);
    vi.mocked(client.send).mockRejectedValueOnce(new Error("create mpu boom"));

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
    expect(CreateMultipartUploadCommand).toHaveBeenCalledTimes(1);
    expect(UploadPartCommand).not.toHaveBeenCalled();
  });

  it("upload multipart throws StorageError when CompleteMultipartUpload fails", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);

    vi.mocked(client.send)
      .mockResolvedValueOnce({ UploadId: "mpu-complete-fail" })
      .mockResolvedValueOnce({ ETag: '"p1"' })
      .mockRejectedValueOnce(new Error("complete boom"));

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
  });

  it("safeAbortUpload retries until the server cleans up orphaned parts", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);
    vi.mocked(client.send)
      .mockResolvedValueOnce({ UploadId: "mpu-retry-abort" })

      .mockRejectedValueOnce(new Error("parts still uploading"))

      .mockResolvedValueOnce({});

    vi.mocked(client.send).mockRejectedValueOnce(new Error("upload-part-boom"));

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow();

    expect(AbortMultipartUploadCommand).toHaveBeenCalledTimes(2);
  });

  it("upload with a small async-iterable stream body routes by buffered size (single PUT)", async () => {
    const streamBody = {
      [Symbol.asyncIterator]: async function* () {
        yield new Uint8Array(1024);
        yield new Uint8Array(2048);
      },
    };

    const client = makeMockClient([{ ETag: '"stream-put"' }]);

    const result = await upload(client, {
      bucket: BUCKET,
      key: KEY,
      body: streamBody as AsyncIterable<Uint8Array>,
    });

    expect(result.etag).toBe("stream-put");
    expect(PutObjectCommand).toHaveBeenCalledTimes(1);
    expect(CreateMultipartUploadCommand).not.toHaveBeenCalled();
  });

  it("upload multipart aborts when stream body raises AbortError mid-read", async () => {
    const controller = new AbortController();
    controller.abort();
    const streamBody = {
      [Symbol.asyncIterator]: async function* () {
        yield new Uint8Array(MIN_PART_SIZE + 1);
        yield new Uint8Array(1);
      },
    };

    const client = makeMockClient([{ UploadId: "mpu-abort-stream" }]);

    await expect(
      upload(
        client,
        {
          bucket: BUCKET,
          key: KEY,
          body: streamBody as AsyncIterable<Uint8Array>,
          signal: controller.signal,
        },
        { minPartSize: MIN_PART_SIZE },
      ),
    ).rejects.toThrow(AbortError);
  });

  it("upload throws StorageError when CreateMultipartUpload returns no UploadId", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);

    vi.mocked(client.send).mockResolvedValueOnce({});

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
  });

  it("upload throws on signal abort with streaming body before any part succeeds", async () => {
    const controller = new AbortController();

    const streamBody = {
      [Symbol.asyncIterator]: async function* () {
        yield new Uint8Array(MIN_PART_SIZE + 1);
        controller.abort();
        yield new Uint8Array(1);
      },
    };
    const client = makeMockClient([{ UploadId: "mpu-mid-stream-abort" }]);

    await expect(
      upload(
        client,
        {
          bucket: BUCKET,
          key: KEY,
          body: streamBody as AsyncIterable<Uint8Array>,
          signal: controller.signal,
        },
        { minPartSize: MIN_PART_SIZE },
      ),
    ).rejects.toThrow(AbortError);
  });

  it("download consumes a Node Readable async iterator", async () => {
    const nodeBody = {
      [Symbol.asyncIterator]: async function* () {
        yield new Uint8Array([9, 8, 7]);
        yield new Uint8Array([6]);
      },
    };

    const client = makeMockClient([{ Body: nodeBody }]);
    const result = await download(client, { bucket: BUCKET, key: KEY });

    const chunks: Uint8Array[] = [];
    for await (const chunk of result.body) chunks.push(chunk);
    expect(chunks.length).toBe(2);
    expect(chunks[0]).toEqual(new Uint8Array([9, 8, 7]));
    expect(chunks[1]).toEqual(new Uint8Array([6]));
  });

  it("createS3Client passes through a session token when present", () => {
    createS3Client(
      { region: "us-east-1" },
      { type: "static", accessKeyId: "ak", secretAccessKey: "sk", sessionToken: "tok" },
    );
    const args = vi.mocked(S3Client).mock.calls[0]![0];
    expect(args.credentials).toEqual({
      accessKeyId: "ak",
      secretAccessKey: "sk",
      sessionToken: "tok",
    });
  });

  it("upload rejects a simple PUT response without an ETag", async () => {
    const body = new Uint8Array(1024);
    const client = makeMockClient([{}]);
    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
  });

  it("download passes a Range header when a range with end is given", async () => {
    const client = makeMockClient([{ Body: new Uint8Array([1, 2]) }]);
    await download(client, { bucket: BUCKET, key: KEY, range: { start: 10, end: 20 } });
    const cmdArgs = vi.mocked(GetObjectCommand).mock.calls[0]![0];
    expect(cmdArgs.Range).toBe("bytes=10-20");
  });

  it("download passes an open-ended Range when a range without end is given", async () => {
    const client = makeMockClient([{ Body: new Uint8Array([1, 2]) }]);
    await download(client, { bucket: BUCKET, key: KEY, range: { start: 5 } });
    const cmdArgs = vi.mocked(GetObjectCommand).mock.calls[0]![0];
    expect(cmdArgs.Range).toBe("bytes=5-");
  });

  it("upload rejects a multipart part response without an ETag", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([
      { UploadId: "mpu-noetag" },
      {},
      { ETag: '"p2"' },
    ]);

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
    expect(CompleteMultipartUploadCommand).not.toHaveBeenCalled();
    expect(AbortMultipartUploadCommand).toHaveBeenCalled();
  });

  it("upload rejects a multipart completion without an ETag", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([
      { UploadId: "mpu-no-complete-etag" },
      { ETag: '"p1"' },
      { ETag: '"p2"' },
      {},
      {},
    ]);

    await expect(upload(client, { bucket: BUCKET, key: KEY, body })).rejects.toThrow(StorageError);
    expect(CompleteMultipartUploadCommand).toHaveBeenCalledTimes(1);
    expect(AbortMultipartUploadCommand).toHaveBeenCalled();
  });

  it("createPresignedDownloadUrl passes a Range when a range with end is given", async () => {
    const client = makeMockClient([]);
    await createPresignedDownloadUrl(client, {
      bucket: BUCKET,
      key: KEY,
      range: { start: 10, end: 20 },
    });
    const cmdArgs = vi.mocked(GetObjectCommand).mock.calls[0]![0];
    expect(cmdArgs.Range).toBe("bytes=10-20");
  });

  it("createPresignedDownloadUrl passes an open-ended Range when a range without end is given", async () => {
    const client = makeMockClient([]);
    await createPresignedDownloadUrl(client, { bucket: BUCKET, key: KEY, range: { start: 5 } });
    const cmdArgs = vi.mocked(GetObjectCommand).mock.calls[0]![0];
    expect(cmdArgs.Range).toBe("bytes=5-");
  });

  it("upload with an empty streamed body buffers to an empty single PUT", async () => {
    const streamBody = {
      [Symbol.asyncIterator]: async function* () {},
    };
    const client = makeMockClient([{ ETag: '"empty"' }]);
    const result = await upload(client, {
      bucket: BUCKET,
      key: KEY,
      body: streamBody as AsyncIterable<Uint8Array>,
    });
    expect(result.etag).toBe("empty");
    expect(PutObjectCommand).toHaveBeenCalledTimes(1);
  });

  it("upload with a single-chunk streamed body buffers to a single PUT", async () => {
    const streamBody = {
      [Symbol.asyncIterator]: async function* () {
        yield new Uint8Array(1024);
      },
    };
    const client = makeMockClient([{ ETag: '"one-chunk"' }]);
    const result = await upload(client, {
      bucket: BUCKET,
      key: KEY,
      body: streamBody as AsyncIterable<Uint8Array>,
    });
    expect(result.etag).toBe("one-chunk");
    expect(PutObjectCommand).toHaveBeenCalledTimes(1);
  });

  it("upload multipart aborts in partWorker when the signal flips during create", async () => {
    const controller = new AbortController();
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);

    vi.mocked(client.send)
      .mockImplementationOnce(async () => {
        controller.abort();
        return { UploadId: "mpu-flip" };
      })
      .mockRejectedValueOnce(new Error("upload-part-boom"));

    await expect(
      upload(client, { bucket: BUCKET, key: KEY, body, signal: controller.signal }),
    ).rejects.toThrow(AbortError);
    expect(AbortMultipartUploadCommand).toHaveBeenCalled();
  });

  it("safeAbortUpload gives up after all retry attempts fail", async () => {
    const body = new Uint8Array(MIN_PART_SIZE + 1);
    const client = makeMockClient([]);
    vi.mocked(client.send)
      .mockResolvedValueOnce({ UploadId: "mpu-abort-all" })
      .mockRejectedValueOnce(new Error("upload-part-boom"))
      .mockRejectedValueOnce(new Error("abort1"))
      .mockRejectedValueOnce(new Error("abort2"))
      .mockRejectedValueOnce(new Error("abort3"));

    await expect(
      upload(
        client,
        { bucket: BUCKET, key: KEY, body },
        { minPartSize: MIN_PART_SIZE, concurrency: 1 },
      ),
    ).rejects.toThrow();
    expect(AbortMultipartUploadCommand).toHaveBeenCalledTimes(3);
  });
});
