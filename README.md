# @shtora/s3poly

Client-side XChaCha20-Poly1305 encryption for S3-compatible object storage. Built by shtora — data is encrypted in your process before it ever reaches the server. The storage backend never sees plaintext or the encryption key.

## Installation

```bash
npm install @shtora/s3poly @aws-sdk/client-s3
# or
bun add @shtora/s3poly @aws-sdk/client-s3
```

`libsodium-wrappers` is included as a dev dependency during build but shipped at runtime. No extra install step required.

## Initialization

Call `initSodium()` once at application startup. Crypto constants are unavailable until it resolves. All sync APIs (`encryptSync`, `decryptSync`) check these constants on entry and throw if they read zero.

```typescript
import { initSodium } from "@shtora/s3poly";

await initSodium();
```

Running this twice is harmless. Calling `initSodium()` is not required if you only use the async `encrypt` generator, which initializes internally before its first yield.

## Encrypt and Upload

```typescript
import { encrypt, initSodium, createR2Client } from "@shtora/s3poly";

const client = createR2Client(
  "your-account-id",
  { type: "static", accessKeyId: "...", secretAccessKey: "..." },
);

async function store(path: string, stream: AsyncIterable<Uint8Array>) {
  const key = await crypto.getRandomValues(new Uint8Array(32));

  const encrypted = encrypt(stream, {
    keyProvider: {
      generateKey: () => Promise.resolve(key),
      resolveKey: () => Promise.resolve(key),
    },
  });

  const chunks: Uint8Array[] = [];
  for await (const chunk of encrypted) {
    chunks.push(chunk);
  }

  return client.send(
    new PutObjectCommand({
      Bucket: "my-bucket",
      Key: path,
      Body: concat(chunks),
    }),
  );
}
```

The `encrypt` function yields the preamble first (5 + HEADERBYTES bytes), then each length-prefixed ciphertext record. Concatenate all yields before sending, or stream them directly if the S3 client accepts an async iterable body.

## Decrypt and Download

```typescript
import { decryptSync, download } from "@shtora/s3poly";

const { body, metadata } = await client.send(
  new GetObjectCommand({ Bucket: "my-bucket", Key: path }),
);

const raw = concat([...body]);
const { plaintext, metadata: cryptoMeta } = decryptSync(raw, key);
```

`decryptSync` reads the preamble, validates version and magic bytes, then walks the record chain sequentially. It throws `FormatError` on structural issues and `AuthenticationError` if any byte was modified.

## Large Files (Multipart Uploads)

Use the standalone `upload` helper. It handles buffering, part splitting, concurrent workers, and abort cleanup automatically.

```typescript
import { upload, createR2Client } from "@shtora/s3poly";

const result = await upload(client, {
  bucket: "my-bucket",
  key: "large-file.enc",
  body: encryptedBody,
  multipartConfig: {
    minPartSize: 10 * 1024 * 1024, // default: 5 MiB
    concurrency: 5,                // default: 5
  },
});

console.log(result.etag);
```

`upload` buffers streamed bodies entirely before deciding between single PUT and multipart. The part-split decision depends on total size, which an unconsumed stream cannot report. Lowering `minPartSize` reduces nothing in memory; it only changes how many parts get created.

## Presigned URLs

For browser-based direct uploads where the server should not handle the payload:

```typescript
import { createPresignedUploadUrl, createPresignedDownloadUrl } from "@shtora/s3poly";

const uploadUrl = await createPresignedUploadUrl(client, {
  bucket: "my-bucket",
  key: "photo.jpg.enc",
}, 3600); // seconds, defaults to 1 hour

const downloadUrl = await createPresignedDownloadUrl(client, {
  bucket: "my-bucket",
  key: "photo.jpg.enc",
  range: { start: 0, end: 1023 },
}, 3600);
```

Presigned URLs pass through the `Range` header when supplied. They do not perform decryption — they sign an S3 GET or PUT request.

## Sync APIs

When you already hold the data in memory:

```typescript
import { encryptSync, decryptSync, concat } from "@shtora/s3poly";

// Encrypt
const { preamble, ciphertext } = encryptSync(data, key, ad);
const stored = concat([preamble, ciphertext]);

// Decrypt
const { plaintext, metadata } = decryptSync(stored, key, ad);
console.log(metadata.byteLength); // BigInt
```

`ad` (additional authenticated data) binds arbitrary context into every record's authentication tag. Supplying the same `ad` value during decrypt is required; a mismatched `ad` triggers `AuthenticationError`. Omit it if you only need confidentiality plus integrity over the ciphertext itself.

## Security Model

**What this protects against:**
- Server-side exposure of plaintext (the storage backend stores only ciphertext)
- Tampering with stored objects (each record is individually authenticated with HMAC-SipHash via Poly1305)
- Replay of individual records (AD binds position and preamble to each tag)

**What this does not protect against:**
- Metadata leakage (object size, content-type, key names remain visible)
- Access control (you still need S3/R2 IAM policies to restrict who can list or delete objects)
- Key management (this package generates and holds keys in process memory; rotating or escrowed keys require your own logic)
- Range-request integrity (downloading a byte range returns raw ciphertext; decryption requires the full preamble and sequential state)

**Algorithm parameters:**
- Cipher: XChaCha20-Poly1305 (secretstream mode)
- Key size: 32 bytes
- Header size: 24 bytes (per-stream nonce)
- Auth tag overhead: 16 bytes per record (ABYTES)
- Max record plaintext: 1 MiB − 16 bytes

## Limits

| Constraint | Value | Notes |
|---|---|---|
| Max record plaintext | ~1 MiB − 16 B | Hardcoded; larger inputs split across records |
| Position counter | 32-bit wrapped | On-wire positions overflow at 2^32 bytes (~4 GiB) |
| Supported versions | V1 (0x01) | Preamble magic bytes: `SDKC` |
| Key size | 32 bytes | Other sizes throw at call time |
| Multipart min part | 5 MiB default | Set explicitly to change; must be positive integer |

## Node.js .read() fallback

When the AWS SDK returns a Node.js `Readable` stream instead of an async iterable, `download` falls back to calling `.read()` repeatedly. A single `null` return ends iteration immediately. This is correct after the stream drains, but a temporary `null` (back-pressure pause) is treated as EOF. The uploaded byte count may differ from what was requested if the remote side sends fewer chunks than expected. Full-body downloads are unaffected because the SDK buffers internally; partial-range requests are where this edge case appears.

## Error Classes

Four error types are exported for precise catch handling:

```typescript
import { AuthenticationError, FormatError, AbortError, StorageError } from "@shtora/s3poly";
```

| Error | When it throws |
|---|---|
| `AuthenticationError` | Ciphertext failedPoly1305 verification; data was modified or the wrong key/AD was used |
| `FormatError` | Bad preamble magic, unsupported version, truncated record, oversized length prefix, non-final message after TAG_FINAL |
| `AbortError` | The provided `AbortSignal` fired during encrypt, decrypt, or upload |
| `StorageError` | Any S3/R2 HTTP failure; wraps the underlying network or service error in `.cause` |

## TypeScript Support

The package ships compiled declarations alongside the JS bundle. `peerDependencies` declares `typescript ^5`; consuming projects should also run TypeScript 5.x for accurate inference on generic exports like `AsyncGenerator<Uint8Array>`.

## Repository

MIT License. Copyright 2026 @shtora/s3poly contributors · shtora
