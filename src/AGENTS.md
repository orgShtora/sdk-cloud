# @shtora/s3poly/src

## OVERVIEW

- V1 uses the SKDC preamble and ordered libsodium secretstream records. S3 helpers transport opaque bytes; they do not encrypt or decrypt objects.

## WHERE TO LOOK

| Need | Start here |
| --- | --- |
| Shared async-iterator cancellation | async.ts |
| Shared wire constants | wire.ts |
| Preamble and length-prefixed record validation | format.ts |
| Sodium initialization, record AD, final-tag state machine | crypto.ts |
| Multipart limits, abort handling, and stream adapters | s3.ts |
| Public input and error contracts | types.ts |

## CONVENTIONS

- Crypto and format import the same magic, version, prefix length, and record limit from wire.ts. PREAMBLE_MAGIC is an exported copy; mutating it must not change parser or writer behavior.
- Record positions are cumulative plaintext bytes encoded in 32 bits and wrap after 2^32 bytes. Keep this wire behavior documented unless changing the format version.
- Await initSodium before synchronous crypto or size discovery. Async encrypt initializes sodium before it asks the key provider for a key.
- Secretstream authenticates the preamble, caller AD, and position on every record. The final record must be an empty TAG_FINAL, and the parser rejects all bytes after it.
- A record prefix describes ciphertext length. MAX_RECORD_BYTES limits ciphertext, so plaintext chunks reserve the libsodium authentication overhead.
- Streamed upload reads through a bounded part buffer and switches to multipart after the single-PUT threshold. Its part size is `minPartSize`, so the stream cap is `min(5 TiB, minPartSize * 10,000)`; known-size `Uint8Array` uploads may grow part size to stay under 10,000 parts. Results are sorted before completion.
- Upload part ETags and the final ETag are required. Failed or cancelled multipart uploads trigger best-effort abort cleanup.
- AbortSignal is passed to S3 requests and used while consuming upload/download streams. Cleanup requests deliberately run without the caller signal so cancellation does not prevent cleanup.
- Download ranges return raw ciphertext; decryption still requires the preamble and sequential secretstream state.
- Supported Node Readable responses use their async iterator. Do not infer EOF from a single read() returning null.
