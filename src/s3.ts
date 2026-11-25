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
import { concat } from "./crypto.js";
import type {
  DownloadInput,
  MultipartConfig,
  S3Config,
  S3Credentials,
  UploadInput,
  UploadResult,
} from "./types.js";
import { AbortError, StorageError } from "./types.js";

const DEFAULT_MIN_PART_SIZE = 5 * 1024 * 1024; // 5 MiB
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

/**
 * Upload data to S3. Uses multipart automatically for large payloads.
 *
 * A `Uint8Array` body reports its length directly; a streamed body is buffered
 * up front (via `collectStream`) because both the route (single PUT vs.
 * multipart) and the part boundaries depend on the total size, which an async
 * iterable cannot report without being consumed. Bodies at or under the minimum
 * part size take a single PUT; anything larger splits into multipart parts.
 */
export async function upload(
  client: S3Client,
  input: UploadInput,
  multipartConfig?: Partial<MultipartConfig>,
): Promise<UploadResult> {
  // Validate multipart tuning options before doing any work. A non-positive or
  // non-finite `minPartSize` would otherwise spin the part-splitting loop (e.g.
  // NaN keeps `offset` frozen at 0) and `concurrency: 0` yields an empty worker
  // pool, so `CompleteMultipartUpload` would be attempted with zero parts.
  const minPartSize = multipartConfig?.minPartSize ?? DEFAULT_MIN_PART_SIZE;
  const concurrency = multipartConfig?.concurrency ?? DEFAULT_CONCURRENCY;

  if (
    typeof minPartSize !== "number" ||
    !Number.isFinite(minPartSize) ||
    !Number.isInteger(minPartSize) ||
    minPartSize <= 0
  ) {
    throw new RangeError("minPartSize must be a positive integer");
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

  // A streamed body is buffered up front: both the upload route (single PUT vs.
  // multipart) and the part boundaries depend on the total size, which an async
  // iterable cannot report without being consumed.
  const data =
    input.body instanceof Uint8Array ? input.body : await collectStream(input.body, input.signal);

  if (data.length <= minPartSize) {
    // Simple put
    const command = new PutObjectCommand({
      Bucket: input.bucket,
      Key: input.key,
      Body: data,
      ContentType: input.contentType,
      Metadata: input.metadata,
    });

    try {
      const response = await client.send(command);
      const etag = response.ETag?.replace(/^"|"$/g, "") ?? "";
      return { etag, key: input.key, bucket: input.bucket };
    } catch (err) {
      throw new StorageError("PUT failed", err);
    }
  }

  return await uploadMultipart(client, input, data, { minPartSize, concurrency });
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
    const response = (await client.send(command)) as GetObjectOutput;
    const body = response.Body;
    if (!body) {
      throw new StorageError("Empty response body");
    }

    return {
      body: streamToAsyncIterable(body),
      metadata: {
        contentType: response.ContentType,
        etag: response.ETag?.replace(/^"|"$/g, ""),
        size: response.ContentLength ? Number(response.ContentLength) : undefined,
      },
    };
  } catch (err) {
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
  input: UploadInput,
  expiresIn = 3600,
): Promise<string> {
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
  data: Uint8Array,
  config: Required<MultipartConfig>,
): Promise<UploadResult> {
  const { minPartSize, concurrency } = config;
  const signal = input.signal;

  // Create multipart upload
  const createCommand = new CreateMultipartUploadCommand({
    Bucket: input.bucket,
    Key: input.key,
    ContentType: input.contentType,
    Metadata: input.metadata,
  });

  let createResponse: CreateMultipartUploadCommandOutput;
  try {
    createResponse = await client.send(createCommand);
  } catch (err) {
    throw new StorageError("CreateMultipartUpload failed", err);
  }

  const uploadId = createResponse.UploadId;
  if (!uploadId) {
    throw new StorageError("No UploadId returned from CreateMultipartUpload");
  }

  const parts: Array<{ partNumber: number; etag: string }> = [];
  let aborted = false;
  let abortError: unknown = null;

  try {
    // Build the ordered list of parts up front.
    const partSpecs: Array<{ partNumber: number; body: Uint8Array }> = [];
    for (let offset = 0; offset < data.length; offset += minPartSize) {
      partSpecs.push({
        partNumber: partSpecs.length + 1,
        body: data.subarray(offset, Math.min(offset + minPartSize, data.length)),
      });
    }

    // Upload parts through a bounded worker pool.
    const pool = Array.from({ length: Math.min(concurrency, partSpecs.length) }, () =>
      partWorker({
        client,
        uploadId,
        bucket: input.bucket,
        key: input.key,
        partSpecs,
        parts,
        isAborted: () => aborted,
        signal,
        markAborted: () => {
          aborted = true;
        },
        setAbortError: (e) => {
          abortError = e;
        },
      }),
    );
    await Promise.all(pool);
    // A worker only sets `aborted` together with `abortError`, so the captured
    // error is the single source of truth for a cancelled or failed part.
    if (abortError) throw abortError;

    // Sort parts by part number and complete.
    parts.sort((a, b) => a.partNumber - b.partNumber);
    const completeCommand = new CompleteMultipartUploadCommand({
      Bucket: input.bucket,
      Key: input.key,
      UploadId: uploadId,
      MultipartUpload: {
        Parts: parts.map((p) => ({ PartNumber: p.partNumber, ETag: p.etag })),
      },
    });

    let response: CompleteMultipartUploadCommandOutput;
    try {
      response = await client.send(completeCommand);
    } catch (err) {
      throw new StorageError("CompleteMultipartUpload failed", err);
    }

    return {
      etag: response.ETag?.replace(/^"|"$/g, "") ?? "",
      key: input.key,
      bucket: input.bucket,
    };
  } catch (err) {
    // On any multipart failure, best-effort clean up the in-progress upload so
    // orphaned parts are not left server-side. The signal is re-checked inside.
    await safeAbortUpload(client, input.bucket, input.key, uploadId);
    throw err;
  }
}

/** Config passed to each worker in the multipart pool. */
interface PartWorkerConfig {
  client: S3Client;
  uploadId: string;
  bucket: string;
  key: string;
  partSpecs: Array<{ partNumber: number; body: Uint8Array }>;
  parts: Array<{ partNumber: number; etag: string }>;
  isAborted: () => boolean;
  signal: AbortSignal | undefined;
  markAborted: () => void;
  setAbortError: (e: unknown) => void;
}

/**
 * Drive the upload of `partSpecs` from a shared index, honoring a concurrency
 * window, so at most one worker owns a part at a time.
 */
async function partWorker(cfg: PartWorkerConfig): Promise<void> {
  const {
    client,
    uploadId,
    bucket,
    key,
    partSpecs,
    parts,
    isAborted,
    signal,
    markAborted,
    setAbortError,
  } = cfg;
  while (true) {
    if (signal?.aborted) {
      markAborted();
      setAbortError(new AbortError());
      return;
    }
    if (isAborted()) return;

    const spec = partSpecs.shift();
    if (!spec) return; // No more parts for this worker.

    const uploadCommand = new UploadPartCommand({
      Bucket: bucket,
      Key: key,
      UploadId: uploadId,
      PartNumber: spec.partNumber,
      Body: spec.body,
    });

    let response: UploadPartCommandOutput;
    try {
      response = await client.send(uploadCommand);
    } catch (err) {
      markAborted();
      setAbortError(new StorageError(`UploadPart ${spec.partNumber} failed`, err));
      return;
    }
    parts.push({ partNumber: spec.partNumber, etag: response.ETag?.replace(/^"|"$/g, "") ?? "" });
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
      // Parts may still be in flight when the abort lands, so back off briefly
      // and retry. If every attempt fails the original error still surfaces.
      if (attempt < maxRetries - 1) await sleep(100 * (attempt + 1));
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Wrap an S3 response body into AsyncIterable&lt;Uint8Array&gt;.
 *
 * Accepts:
 * - `Uint8Array` (already complete) — returns a single-item iterable.
 * - Web ReadableStream (`Symbol.asyncIterator`) — returned by the AWS SDK in browsers.
 * - Node.js `Readable` with `.read()` — returned by the AWS SDK in Node/Bun.
 *
 * Any other shape throws `StorageError("Unsupported S3 response body type")`.
 * The caller must ensure the client was configured for a runtime that the AWS
 * SDK supports; the SDK does not return exotic stream types.
 */
function streamToAsyncIterable(body: unknown): AsyncIterable<Uint8Array> {
  // A plain Uint8Array body is already a single complete chunk.
  if (body instanceof Uint8Array) {
    return {
      [Symbol.asyncIterator]() {
        let done = false;
        return {
          async next() {
            if (done) return { done: true, value: undefined };
            done = true;
            return { done: false, value: body };
          },
        };
      },
    };
  }

  // Handle async-iterable bodies (Web ReadableStream, AWS SDK streams).
  if (body && typeof body === "object" && Symbol.asyncIterator in body) {
    const it = (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
    return {
      [Symbol.asyncIterator]() {
        return it;
      },
    };
  }

  // Node.js readable stream exposes .read().
  const read = (body as { read?: () => Uint8Array | null }).read;
  if (typeof read !== "function") {
    throw new StorageError("Unsupported S3 response body type");
  }

  return {
    [Symbol.asyncIterator]() {
      return {
        async next() {
          const chunk = read();
          if (chunk === null) {
            return { done: true, value: undefined };
          }
          return { done: false, value: chunk };
        },
      };
    },
  };
}

/**
 * Buffer a streamed upload body. The upload route (single PUT vs. multipart)
 * and the part boundaries both depend on the total size, which an async
 * iterable cannot report without being consumed.
 */
async function collectStream(
  body: AsyncIterable<Uint8Array>,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of body) {
    if (signal?.aborted) throw new AbortError();
    chunks.push(chunk);
  }
  return concat(chunks);
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
