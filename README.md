# @shtora/s3poly

Encrypt and authenticate data with libsodium secretstream, then store the ciphertext through an S3-compatible API. Your application supplies and manages the encryption key.

## Installation

```bash
npm install @shtora/s3poly @aws-sdk/client-s3
# or
bun add @shtora/s3poly @aws-sdk/client-s3
```

`libsodium-wrappers` is included as a dev dependency during build but shipped at runtime. No extra install step required.

## Initialization

Call `initSodium()` once at application startup. Crypto constants are unavailable until it resolves. All sync APIs (`encryptSync`, `decryptSync`) require sodium initialization and throw a clear error if it has not completed.

```typescript
import { initSodium } from "@shtora/s3poly";

await initSodium();
```

Running this twice is harmless. Calling `initSodium()` is not required if you only use the async `encrypt` generator, which initializes internally before its first yield.

## Encrypt and Upload

```typescript
import { createR2Client, encrypt, upload } from "@shtora/s3poly";

const client = createR2Client("your-account-id", {
  type: "static",
  accessKeyId: "...",
  secretAccessKey: "...",
});

async function store(path: string, stream: AsyncIterable<Uint8Array>) {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const result = await upload(client, {
    bucket: "my-bucket",
    key: path,
    body: encrypt(stream, {
      keyProvider: { generateKey: async () => key },
    }),
    contentType: "application/octet-stream",
  });

  // Persist this key through your key-management system, separately from the object.
  return { result, key };
}
```

The encrypt generator yields the preamble and length-prefixed ciphertext records. For streamed bodies, upload reads only enough to choose single PUT or multipart, then sends multipart parts as it consumes the stream.

## Decrypt and Download

```typescript
import type { S3Client } from "@aws-sdk/client-s3";
import { concat, decryptSync, download } from "@shtora/s3poly";

async function restore(client: S3Client, path: string, key: Uint8Array) {
  const { body } = await download(client, { bucket: "my-bucket", key: path });
  const chunks: Uint8Array[] = [];
  for await (const chunk of body) chunks.push(chunk);

  const encrypted = concat(chunks);
  return decryptSync(encrypted, key);
}
```

download returns an async iterable of raw ciphertext. decryptSync requires the complete encrypted object in memory and throws FormatError for malformed framing or AuthenticationError if a record fails authentication.

## Large Files (Multipart Uploads)

The upload helper automatically selects multipart for larger payloads. Multipart size and concurrency belong in the third argument:

~~~typescript
import type { S3Client } from "@aws-sdk/client-s3";
import { upload } from "@shtora/s3poly";

async function storeLarge(
  client: S3Client,
  encryptedBody: AsyncIterable<Uint8Array>,
) {
  return await upload(
    client,
    {
      bucket: "my-bucket",
      key: "large-file.enc",
      body: encryptedBody,
    },
    {
      minPartSize: 10 * 1024 * 1024, // default: 5 MiB
      concurrency: 5, // default: 5
    },
  );
}
~~~

S3 requires multipart parts from 5 MiB to 5 GiB, allows at most 10,000 parts, and caps an object at 5 TiB. For streamed bodies, `minPartSize` is also the part size, so the maximum stream size is `min(5 TiB, minPartSize × 10,000)`. With the default 5 MiB part size, the cap is 50,000 MiB. Increase `minPartSize` to raise it. Stream upload memory is bounded by the configured part size, concurrency, and the size of chunks yielded by the source. `Uint8Array` uploads can use larger parts chosen from their known length.

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

function roundTrip(data: Uint8Array, key: Uint8Array, ad?: Uint8Array) {
  const { preamble, ciphertext } = encryptSync(data, key, ad);
  const stored = concat([preamble, ciphertext]);
  const { plaintext, metadata } = decryptSync(stored, key, ad);
  return { plaintext, byteLength: metadata.byteLength };
}
```

`ad` (additional authenticated data) binds arbitrary context into every record's authentication tag. Supplying the same `ad` value during decrypt is required; a mismatched `ad` triggers `AuthenticationError`. Omit it if you only need confidentiality plus integrity over the ciphertext itself.

## Wire format V1

The preamble is `SKDC` (4 bytes), version `0x01` (1 byte), and the libsodium secretstream header (24 bytes). It is followed by records encoded as a 4-byte big-endian ciphertext length and that many ciphertext bytes. Each data record uses `TAG_MESSAGE`; the stream ends with an authenticated empty `TAG_FINAL` record. Bytes after the final record are rejected.

Each record's associated data is `caller AD || preamble || plaintext position`, where plaintext position is an unsigned 32-bit big-endian byte count that wraps after 2^32 bytes. Omitting caller AD removes the first component.

## Security Model

**What this protects against:**
- Server-side exposure of plaintext (the storage backend stores only ciphertext)
- Tampering with stored objects (each record has an XChaCha20-Poly1305 authentication tag)
- Replay of individual records (AD binds position and preamble to each tag)

**What this does not protect against:**
- Metadata leakage (object size, content-type, key names remain visible)
- Access control (you still need S3/R2 IAM policies to restrict who can list or delete objects)
- Key management (your key provider supplies the key; persistence, rotation, escrow, and access control are application responsibilities)
- Range-request integrity (downloading a byte range returns raw ciphertext; decryption requires the full preamble and sequential state)

**Algorithm parameters:**
- Cipher: XChaCha20-Poly1305 (secretstream mode)
- Key size: 32 bytes
- Header size: 24 bytes (per-stream nonce)
- Secretstream overhead: 17 bytes per record (ABYTES: 1 tag byte + 16-byte Poly1305 MAC)
- Max record plaintext: 1,048,559 bytes (1 MiB − 17 bytes)

## Limits

| Constraint | Value | Notes |
|---|---|---|
| Max record plaintext | 1,048,559 B | Larger inputs split across records |
| Position counter | 32-bit wrapped | On-wire positions overflow at 2^32 bytes (~4 GiB) |
| Supported versions | V1 (0x01) | Preamble magic bytes: `SKDC` |
| Key size | 32 bytes | Other sizes throw at call time |
| Multipart part size | 5 MiB to 5 GiB | Default is 5 MiB; part count is capped at 10,000 |
| Multipart object size | 5 TiB | S3 service limit; streamed-body limit also depends on `minPartSize` and the 10,000-part cap |
| Single PUT size | 5 GiB | Larger objects use multipart |

## Stream and memory behavior

Node.js Readable responses are consumed through their async iterator. The library does not use read() as an EOF check. Streamed uploads retain a bounded set of multipart buffers. `decryptSync` still buffers the complete ciphertext and plaintext; use it when that memory cost fits your workload.

## Error Classes

Four error types are exported for precise catch handling:

```typescript
import { AuthenticationError, FormatError, AbortError, StorageError } from "@shtora/s3poly";
```

| Error | When it throws |
|---|---|
| `AuthenticationError` | Record authentication failed; the data, key, or associated data may be wrong |
| `FormatError` | Bad preamble magic, unsupported version, truncated record, oversized record, or bytes after TAG_FINAL |
| `AbortError` | The provided `AbortSignal` cancelled encryption, upload, a request, or body consumption |
| `StorageError` | An S3/R2 request or response failed; wraps the underlying error in `.cause` when available |

## TypeScript Support

The package ships compiled declarations alongside the JS bundle. `peerDependencies` declares `typescript ^5`; consuming projects should also run TypeScript 5.x for accurate inference on generic exports like `AsyncGenerator<Uint8Array>`.

## Repository

MIT License. Copyright 2026 @shtora/s3poly contributors · shtora
