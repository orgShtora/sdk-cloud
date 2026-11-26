export {
  concat,
  decryptSync,
  encrypt,
  encryptSync,
  getAbytes,
  getHeaderBytes,
  getKeyBytes,
  getPreambleLength,
  getTagFinal,
  getTagMessage,
  initSodium,
  isSodiumReady,
} from "./crypto.js";
export {
  buildRecordAd,
  encodeRecord,
  LENGTH_PREFIX_SIZE,
  MAX_RECORD_BYTES,
  PREAMBLE_MAGIC,
  readPreamble,
  readRecord,
  VERSION_V1,
  writePreamble,
} from "./format.js";
export {
  createPresignedDownloadUrl,
  createPresignedUploadUrl,
  createR2Client,
  createS3Client,
  download,
  upload,
} from "./s3.js";
export type {
  CryptoOptions,
  DecryptedMetadata,
  DownloadInput,
  KeyProvider,
  MultipartConfig,
  PresignedUploadInput,
  S3Config,
  S3Credentials,
  UploadInput,
  UploadResult,
} from "./types.js";
export {
  AbortError,
  AuthenticationError,
  FormatError,
  StorageError,
} from "./types.js";
