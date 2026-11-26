export interface KeyProvider {
  generateKey(): Promise<Uint8Array>;
}

export interface CryptoOptions {
  keyProvider: KeyProvider;

  ad?: Uint8Array;

  signal?: AbortSignal;

  maxChunkSize?: number;
}

export interface DecryptedMetadata {
  byteLength: bigint;

  preamble: Uint8Array;
}

export interface S3Config {
  region: string;

  endpoint?: string;

  forcePathStyle?: boolean;
}

export type S3Credentials =
  | { type: "static"; accessKeyId: string; secretAccessKey: string; sessionToken?: string }
  | { type: "temp"; accessKeyId: string; secretAccessKey: string; sessionToken: string };

export interface UploadInput {
  bucket: string;
  key: string;
  body: ReadableStream<Uint8Array> | AsyncIterable<Uint8Array> | Uint8Array;

  contentType?: string;

  metadata?: Record<string, string>;

  signal?: AbortSignal;
}

export type PresignedUploadInput = Pick<UploadInput, "bucket" | "key" | "contentType" | "metadata">;

export interface UploadResult {
  etag: string;
  key: string;
  bucket: string;
}

export interface DownloadInput {
  bucket: string;
  key: string;

  range?: { start: number; end?: number };

  signal?: AbortSignal;
}

export interface MultipartConfig {
  minPartSize?: number;

  concurrency?: number;
}

export class AuthenticationError extends Error {
  override readonly name = "AuthenticationError";
  constructor(message: string) {
    super(message);
  }
}

export class FormatError extends Error {
  override readonly name = "FormatError";
  constructor(message: string) {
    super(message);
  }
}

export class AbortError extends Error {
  override readonly name = "AbortError";
  constructor(message?: string) {
    super(message ?? "Operation aborted");
  }
}

export class StorageError extends Error {
  override readonly name = "StorageError";
  constructor(
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
  }
}
