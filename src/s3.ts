import type {
  CompleteMultipartUploadCommandOutput,
  CreateMultipartUploadCommandOutput,
  GetObjectOutput,
  UploadPartCommandOutput,
} from "@aws-sdk/client-s3";
import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
  type S3ClientConfig,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { nextWithSignal } from "./async.js";
import { concat } from "./crypto.js";
import type {
  DownloadInput,
  MultipartConfig,
  PresignedUploadInput,
  S3Config,
  S3Credentials,
  UploadInput,
  UploadResult,
} from "./types.js";
import { AbortError, StorageError } from "./types.js";

const DEFAULT_MIN_PART_SIZE = 5 * 1024 * 1024; // 5 MiB
const MAX_PART_SIZE = 5 * 1024 ** 3; // 5 GiB
const MAX_PARTS = 10_000;
const MAX_OBJECT_SIZE = 5 * 1024 ** 4; // 5 TiB
const MAX_PRESIGNED_URL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_CONCURRENCY = 5;

/**
 * Create an S3 client from configuration and credentials.
 */
export function createS3Client(config: S3Config, credentials: S3Credentials): S3Client {
  const clientConfig: S3ClientConfig = {
    region: config.region,
    forcePathStyle: config.forcePathStyle ?? false,
    credentials: {
      accessKeyId: credentials.accessKeyId,
      secretAccessKey: credentials.secretAccessKey,
      ...(credentials.sessionToken ? { sessionToken: credentials.sessionToken } : {}),
    },
  };

  if (config.endpoint) {
    clientConfig.endpoint = config.endpoint;
  }

  return new S3Client(clientConfig);
}

/** Upload data to S3, using multipart for bodies larger than the configured part size. */
export async function upload(
  client: S3Client,
  input: UploadInput,
  multipartConfig?: Partial<MultipartConfig>,
): Promise<UploadResult> {
  // Validate multipart tuning options before consuming the body. Part sizes
  // must obey S3's limits, and concurrency must leave at least one worker.
  const minPartSize = multipartConfig?.minPartSize ?? DEFAULT_MIN_PART_SIZE;
  const concurrency = multipartConfig?.concurrency ?? DEFAULT_CONCURRENCY;

  if (
    typeof minPartSize !== "number" ||
    !Number.isFinite(minPartSize) ||
    !Number.isInteger(minPartSize) ||
    minPartSize < DEFAULT_MIN_PART_SIZE ||
    minPartSize > MAX_PART_SIZE
  ) {
    throw new RangeError(
      `minPartSize must be an integer between ${DEFAULT_MIN_PART_SIZE} and ${MAX_PART_SIZE} bytes`,
    );
  }
  if (
    typeof concurrency !== "number" ||
    !Number.isFinite(concurrency) ||
    !Number.isInteger(concurrency) ||
    concurrency <= 0
  ) {
    throw new RangeError("concurrency must be a positive integer");
  }

  if (input.signal?.aborted) throw new AbortError();

  const requestController = new AbortController();
  const abortFromCaller = () => requestController.abort(input.signal?.reason);
  input.signal?.addEventListener("abort", abortFromCaller, { once: true });

  try {
    if (input.body instanceof Uint8Array) {
      const data = input.body;
      if (data.length > MAX_OBJECT_SIZE) {
        throw new RangeError(`Object exceeds the S3 maximum size of ${MAX_OBJECT_SIZE} bytes`);
      }

      if (data.length <= minPartSize) {
        return await putObject(client, input, data, requestController.signal);
      }

      const partSize = Math.max(minPartSize, Math.ceil(data.length / MAX_PARTS));
      if (partSize > MAX_PART_SIZE) {
        throw new RangeError("The object requires a multipart part larger than the S3 limit");
      }

      return await uploadMultipart(client, input, bufferedParts(data, partSize), {
        concurrency,
        requestController,
        callerSignal: input.signal,
      });
    }

    const maxStreamBytes = Math.min(MAX_OBJECT_SIZE, minPartSize * MAX_PARTS);
    const streamLimitMessage =
      maxStreamBytes < MAX_OBJECT_SIZE
        ? `Streamed object exceeds ${maxStreamBytes} bytes for the configured part size and S3 part-count limit`
        : `Object exceeds the S3 maximum size of ${MAX_OBJECT_SIZE} bytes`;
    const reader = new UploadByteReader(
      input.body,
      requestController.signal,
      maxStreamBytes,
      minPartSize,
      streamLimitMessage,
    );

    try {
      const initial = await reader.read(minPartSize + 1);
      if (reader.done && initial.length <= minPartSize) {
        return await putObject(client, input, initial, requestController.signal);
      }

      return await uploadMultipart(client, input, streamedParts(initial, reader, minPartSize), {
        concurrency,
        requestController,
        callerSignal: input.signal,
      });
    } finally {
      await reader.return();
    }
  } catch (err) {
    if (input.signal?.aborted) throw new AbortError();
    throw err;
  } finally {
    input.signal?.removeEventListener("abort", abortFromCaller);
  }
}

async function putObject(
  client: S3Client,
  input: UploadInput,
  data: Uint8Array,
  signal: AbortSignal,
): Promise<UploadResult> {
  const command = new PutObjectCommand({
    Bucket: input.bucket,
    Key: input.key,
    Body: data,
    ContentType: input.contentType,
    Metadata: input.metadata,
  });

  try {
    const response = await client.send(command, { abortSignal: signal });
    return { etag: requireEtag(response.ETag, "PUT"), key: input.key, bucket: input.bucket };
  } catch (err) {
    if (input.signal?.aborted) throw new AbortError();
    if (err instanceof StorageError) throw err;
    throw new StorageError("PUT failed", err);
  }
}

/**
 * Download data from S3.
 */
export async function download(
  client: S3Client,
  input: DownloadInput,
): Promise<{
  body: AsyncIterable<Uint8Array>;
  metadata: { contentType?: string; etag?: string; size?: number };
}> {
  validateRange(input.range);
  const command = new GetObjectCommand({
    Bucket: input.bucket,
    Key: input.key,
    ...(input.range
      ? {
          Range: `bytes=${input.range.start}-${input.range.end ?? ""}`,
        }
      : {}),
  });

  try {
    const response = (await client.send(command, { abortSignal: input.signal })) as GetObjectOutput;
    const body = response.Body;
    if (!body) {
      throw new StorageError("Empty response body");
    }

    return {
      body: streamToAsyncIterable(body, input.signal),
      metadata: {
        contentType: response.ContentType,
        etag: response.ETag?.replace(/^"|"$/g, ""),
        size: response.ContentLength === undefined ? undefined : Number(response.ContentLength),
      },
    };
  } catch (err) {
    if (input.signal?.aborted) throw new AbortError();
    if (err instanceof StorageError) throw err;
    throw new StorageError("GET failed", err);
  }
}

/**
 * Generate a presigned URL for uploading to S3.
 * Useful for browser direct uploads.
 *
 * @param expiresIn  Seconds until the URL expires. Default: 3600 (1 h).
 */
export async function createPresignedUploadUrl(
  client: S3Client,
  input: PresignedUploadInput,
  expiresIn = 3600,
): Promise<string> {
  validateExpiresIn(expiresIn);
  const command = new PutObjectCommand({
    Bucket: input.bucket,
    Key: input.key,
    ContentType: input.contentType,
    Metadata: input.metadata,
  });

  try {
    return await getSignedUrl(client, command, { expiresIn });
  } catch (err) {
    throw new StorageError("Failed to create presigned URL", err);
  }
}

/**
 * Generate a presigned URL for downloading from S3.
 *
 * @param expiresIn  Seconds until the URL expires. Default: 3600 (1 h).
 */
export async function createPresignedDownloadUrl(
  client: S3Client,
  input: DownloadInput,
  expiresIn = 3600,
): Promise<string> {
  validateExpiresIn(expiresIn);
  validateRange(input.range);
  const command = new GetObjectCommand({
    Bucket: input.bucket,
    Key: input.key,
    ...(input.range
      ? {
          Range: `bytes=${input.range.start}-${input.range.end ?? ""}`,
        }
      : {}),
  });

  try {
    return await getSignedUrl(client, command, { expiresIn });
  } catch (err) {
    throw new StorageError("Failed to create presigned URL", err);
  }
}

/**
 * Perform a multipart upload with a bounded worker pool.
 */
async function uploadMultipart(
  client: S3Client,
  input: UploadInput,
  partBodies: AsyncIterable<Uint8Array>,
  config: {
    concurrency: number;
    requestController: AbortController;
    callerSignal: AbortSignal | undefined;
  },
): Promise<UploadResult> {
  const { concurrency, requestController, callerSignal } = config;
  if (callerSignal?.aborted) throw new AbortError();

  let uploadId: string | undefined;
  let multipartCompleted = false;
  try {
    const createCommand = new CreateMultipartUploadCommand({
      Bucket: input.bucket,
      Key: input.key,
      ContentType: input.contentType,
      Metadata: input.metadata,
    });

    let createResponse: CreateMultipartUploadCommandOutput;
    try {
      createResponse = await client.send(createCommand, { abortSignal: requestController.signal });
    } catch (err) {
      if (callerSignal?.aborted) throw new AbortError();
      throw new StorageError("CreateMultipartUpload failed", err);
    }

    const createdUploadId = createResponse.UploadId;
    if (!createdUploadId) throw new StorageError("No UploadId returned from CreateMultipartUpload");
    uploadId = createdUploadId;

    const parts: Array<{ partNumber: number; etag: string }> = [];
    let aborted = false;
    let abortError: unknown = null;

    const partIterator = partBodies[Symbol.asyncIterator]();
    let nextPartNumber = 1;
    let iteratorLock = Promise.resolve();
    const nextPartSpec = async () => {
      let release = () => {};
      const previous = iteratorLock;
      iteratorLock = new Promise<void>((resolve) => {
        release = resolve;
      });
      await previous;
      try {
        if (aborted) return undefined;
        const next = await partIterator.next();
        if (next.done) return undefined;
        if (nextPartNumber > MAX_PARTS) {
          throw new RangeError(`Multipart upload cannot exceed ${MAX_PARTS} parts`);
        }
        return { partNumber: nextPartNumber++, body: next.value };
      } finally {
        release();
      }
    };

    const pool = Array.from({ length: Math.min(concurrency, MAX_PARTS) }, () =>
      partWorker({
        client,
        uploadId: createdUploadId,
        bucket: input.bucket,
        key: input.key,
        nextPartSpec,
        parts,
        isAborted: () => aborted,
        requestSignal: requestController.signal,
        callerSignal,
        markAborted: () => {
          aborted = true;
        },
        abortRequests: () => requestController.abort(),
        setAbortError: (error) => {
          if (abortError === null) abortError = error;
        },
      }),
    );

    await Promise.all(pool);
    if (abortError) throw abortError;
    if (callerSignal?.aborted) throw new AbortError();

    parts.sort((a, b) => a.partNumber - b.partNumber);
    const completeCommand = new CompleteMultipartUploadCommand({
      Bucket: input.bucket,
      Key: input.key,
      UploadId: createdUploadId,
      MultipartUpload: {
        Parts: parts.map((part) => ({ PartNumber: part.partNumber, ETag: part.etag })),
      },
    });

    let response: CompleteMultipartUploadCommandOutput;
    try {
      response = await client.send(completeCommand, { abortSignal: requestController.signal });
      multipartCompleted = true;
    } catch (err) {
      if (callerSignal?.aborted) throw new AbortError();
      throw new StorageError("CompleteMultipartUpload failed", err);
    }

    if (callerSignal?.aborted) throw new AbortError();
    return {
      etag: requireEtag(response.ETag, "CompleteMultipartUpload"),
      key: input.key,
      bucket: input.bucket,
    };
  } catch (err) {
    requestController.abort();
    if (uploadId && !multipartCompleted) {
      await safeAbortUpload(client, input.bucket, input.key, uploadId);
    }
    if (callerSignal?.aborted) throw new AbortError();
    throw err;
  }
}

/** Config passed to each worker in the multipart pool. */
interface PartWorkerConfig {
  client: S3Client;
  uploadId: string;
  bucket: string;
  key: string;
  nextPartSpec: () => Promise<{ partNumber: number; body: Uint8Array } | undefined>;
  parts: Array<{ partNumber: number; etag: string }>;
  isAborted: () => boolean;
  requestSignal: AbortSignal;
  callerSignal: AbortSignal | undefined;
  markAborted: () => void;
  abortRequests: () => void;
  setAbortError: (error: unknown) => void;
}

async function partWorker(cfg: PartWorkerConfig): Promise<void> {
  const {
    client,
    uploadId,
    bucket,
    key,
    nextPartSpec,
    parts,
    isAborted,
    requestSignal,
    callerSignal,
    markAborted,
    abortRequests,
    setAbortError,
  } = cfg;

  while (true) {
    if (callerSignal?.aborted) {
      markAborted();
      setAbortError(new AbortError());
      abortRequests();
      return;
    }
    if (isAborted()) return;

    let spec: { partNumber: number; body: Uint8Array } | undefined;
    try {
      spec = await nextPartSpec();
    } catch (err) {
      if (!isAborted()) {
        markAborted();
        setAbortError(err);
        abortRequests();
      }
      return;
    }
    if (!spec) return;

    const uploadCommand = new UploadPartCommand({
      Bucket: bucket,
      Key: key,
      UploadId: uploadId,
      PartNumber: spec.partNumber,
      Body: spec.body,
    });

    try {
      const response: UploadPartCommandOutput = await client.send(uploadCommand, {
        abortSignal: requestSignal,
      });
      const etag = response.ETag?.replace(/^"|"$/g, "");
      if (!etag) throw new StorageError(`UploadPart ${spec.partNumber} returned no ETag`);
      parts.push({ partNumber: spec.partNumber, etag });
    } catch (err) {
      if (!isAborted()) {
        markAborted();
        setAbortError(
          callerSignal?.aborted
            ? new AbortError()
            : new StorageError(`UploadPart ${spec.partNumber} failed`, err),
        );
        abortRequests();
      }
      return;
    }
  }
}

/**
 * Best-effort cleanup of an in-progress multipart upload, retried per AWS
 * guidance. Orphaned parts stay billed, so this runs even after an abort.
 */
async function safeAbortUpload(
  client: S3Client,
  bucket: string,
  key: string,
  uploadId: string,
): Promise<void> {
  const maxRetries = 3;

  // Cleanup runs even when the caller aborted: parts left behind stay billed.
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const abortCommand = new AbortMultipartUploadCommand({
        Bucket: bucket,
        Key: key,
        UploadId: uploadId,
      });
      await client.send(abortCommand);
      return;
    } catch {
      // Parts may still be in flight when the abort lands, so retry with
      // exponential full jitter. The original error still surfaces.
      if (attempt < maxRetries - 1) await sleep(Math.random() * 100 * 2 ** attempt);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requireEtag(etag: string | undefined, operation: string): string {
  const normalized = etag?.replace(/^"|"$/g, "");
  if (!normalized) throw new StorageError(`${operation} did not return an ETag`);
  return normalized;
}

function validateRange(range: DownloadInput["range"]): void {
  if (!range) return;
  if (!Number.isSafeInteger(range.start) || range.start < 0) {
    throw new RangeError("Range start must be a non-negative safe integer");
  }
  if (
    range.end !== undefined &&
    (!Number.isSafeInteger(range.end) || range.end < range.start)
  ) {
    throw new RangeError("Range end must be a safe integer greater than or equal to start");
  }
}

function validateExpiresIn(expiresIn: number): void {
  if (
    !Number.isInteger(expiresIn) ||
    expiresIn < 1 ||
    expiresIn > MAX_PRESIGNED_URL_SECONDS
  ) {
    throw new RangeError(`expiresIn must be between 1 and ${MAX_PRESIGNED_URL_SECONDS} seconds`);
  }
}

/**
 * Adapt supported S3 response bodies to an async iterable and propagate
 * cancellation through the request body while the caller consumes it.
 */
function streamToAsyncIterable(body: unknown, signal?: AbortSignal): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator]() {
      const iterator = getByteIterator(body);
      let completed = false;
      try {
        while (true) {
          const result = await nextWithSignal(iterator, signal);
          if (result.done) {
            completed = true;
            return;
          }
          yield result.value;
        }
      } catch (err) {
        if (signal?.aborted) throw new AbortError();
        throw err;
      } finally {
        if (!completed) {
          void Promise.resolve(iterator.return?.()).catch(() => undefined);
        }
      }
    },
  };
}

function getByteIterator(body: unknown): AsyncIterator<Uint8Array> {
  if (body instanceof Uint8Array) {
    let done = false;
    return {
      async next() {
        if (done) return { done: true, value: undefined };
        done = true;
        return { done: false, value: body };
      },
    };
  }

  if (body && typeof body === "object") {
    const asyncIterator = (body as { [Symbol.asyncIterator]?: () => AsyncIterator<Uint8Array> })[
      Symbol.asyncIterator
    ];
    if (typeof asyncIterator === "function") return asyncIterator.call(body);

    const getReader = (body as { getReader?: () => unknown }).getReader;
    if (typeof getReader === "function") {
      const reader = getReader.call(body) as {
        read: () => Promise<IteratorResult<Uint8Array>>;
        cancel?: () => Promise<void>;
        releaseLock?: () => void;
      };
      return {
        async next() {
          const result = await reader.read();
          if (result.done) reader.releaseLock?.();
          return result;
        },
        async return() {
          try {
            await reader.cancel?.();
          } finally {
            reader.releaseLock?.();
          }
          return { done: true, value: undefined };
        },
      };
    }
  }

  throw new StorageError("Unsupported S3 response body type");
}

function bufferedParts(data: Uint8Array, partSize: number): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator]() {
      for (let offset = 0; offset < data.length; offset += partSize) {
        yield data.subarray(offset, Math.min(offset + partSize, data.length));
      }
    },
  };
}

class UploadByteReader implements AsyncIterableIterator<Uint8Array> {
  private readonly iterator: AsyncIterator<Uint8Array>;
  private current: Uint8Array | undefined;
  private offset = 0;
  private sourceDone = false;
  private totalBytes = 0;

  constructor(
    body: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array>,
    private readonly signal: AbortSignal,
    private readonly maxBytes: number,
    private readonly chunkSize: number,
    private readonly limitMessage: string,
  ) {
    this.iterator = streamToAsyncIterable(body, signal)[Symbol.asyncIterator]();
  }

  get done(): boolean {
    return this.sourceDone && this.current === undefined;
  }

  async read(maxBytes: number): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let bytesRead = 0;

    while (bytesRead < maxBytes && !this.sourceDone) {
      if (!this.current) {
        const next = await nextWithSignal(this.iterator, this.signal);
        if (next.done) {
          this.sourceDone = true;
          break;
        }
        this.current = next.value;
        this.offset = 0;
      }

      if (this.current.length === 0) {
        this.current = undefined;
        continue;
      }

      const take = Math.min(maxBytes - bytesRead, this.current.length - this.offset);
      if (take > this.maxBytes - this.totalBytes) throw new RangeError(this.limitMessage);

      chunks.push(this.current.subarray(this.offset, this.offset + take));
      this.totalBytes += take;
      bytesRead += take;
      this.offset += take;
      if (this.offset === this.current.length) {
        this.current = undefined;
        this.offset = 0;
      }
    }

    if (chunks.length === 0) return new Uint8Array(0);
    return chunks.length === 1 ? chunks[0]!.slice() : concat(chunks);
  }

  async next(): Promise<IteratorResult<Uint8Array>> {
    const value = await this.read(this.chunkSize);
    return value.length === 0 ? { done: true, value: undefined } : { done: false, value };
  }

  async return(): Promise<IteratorResult<Uint8Array>> {
    this.sourceDone = true;
    this.current = undefined;
    void Promise.resolve(this.iterator.return?.()).catch(() => undefined);
    return { done: true, value: undefined };
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<Uint8Array> {
    return this;
  }
}

function streamedParts(
  initial: Uint8Array,
  reader: UploadByteReader,
  partSize: number,
): AsyncIterable<Uint8Array> {
  return {
    async *[Symbol.asyncIterator]() {
      const input = (async function* () {
        if (initial.length > 0) yield initial;
        for await (const chunk of reader) yield chunk;
      })();

      let chunks: Uint8Array[] = [];
      let partBytes = 0;
      for await (const chunk of input) {
        let offset = 0;
        while (offset < chunk.length) {
          const take = Math.min(partSize - partBytes, chunk.length - offset);
          chunks.push(chunk.subarray(offset, offset + take));
          partBytes += take;
          offset += take;

          if (partBytes === partSize) {
            yield concat(chunks);
            chunks = [];
            partBytes = 0;
          }
        }
      }

      if (partBytes > 0) yield concat(chunks);
    },
  };
}

/**
 * R2-specific configuration helper.
 */
export function createR2Client(
  accountId: string,
  credentials: S3Credentials,
  region = "auto",
  endpoint?: string,
): S3Client {
  return createS3Client(
    {
      region,
      endpoint: endpoint ?? `https://${accountId}.r2.cloudflarestorage.com`,
      forcePathStyle: true,
    },
    credentials,
  );
}
