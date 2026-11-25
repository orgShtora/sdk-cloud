# @shtora/s3poly/src

## OVERVIEW

- Sequential secretstream state authenticates a V1 preamble and ordered records; S3 uploads and downloads remain opaque byte transport (`crypto.ts:92-334`; `s3.ts:96-150`).

## WHERE TO LOOK

| Need | Start here |
| --- | --- |
| Sodium initialization and size gates | `crypto.ts:5-49,92-121,175-196,243-296` |
| Record AD and final-tag state machine | `crypto.ts:55-73,123-172,193-232,273-327`; `format.ts:95-116` |
| Caller-key preservation regression | `crypto.test.ts:167-177`; implementation at `crypto.ts:243-249,273,307-309` |
| Post-final trailing-input coverage | `crypto.test.ts:432-441`; parser at `crypto.ts:278-327` |
| Upload buffering, multipart ordering, and cleanup | `s3.ts:96-118,245-310,332-403,475-484` |
| Download ranges and body adaptation | `s3.ts:124-158,422-468`; `types.ts:53-60` |
| Node `.read()` fallback regression | `s3.test.ts:470-488` |

## CONVENTIONS

- Record position is cumulative plaintext bytes, not a record index or ciphertext offset; encryption advances by `msg.length`, decryption by `message.length` (`crypto.ts:123,136,150,194,203,212,276,304,313-320`).
- On-wire positions use only the low 32 bits and wrap every 2^32 plaintext bytes; widening only public `buildRecordAd` cannot change the private crypto path (`crypto.ts:55-59,62-73`; `format.ts:98-115`).
- Await `initSodium()` before sync use or key-size discovery: size globals start at zero, sync APIs compare keys against `_keyBytes`, and async `encrypt` calls `generateKey()` before initialization, so early sync calls reject ordinary keys and a first-run provider calling `getKeyBytes()` observes zero (`crypto.ts:5-26,47-49,107-108,180-181,248-249`).

## ANTI-PATTERNS

- Do not substitute public `buildRecordAd` for crypto's private builder: production AD is `callerAD || preamble || position`, while the public helper omits caller AD and would drop `CryptoOptions.ad` authentication (`crypto.ts:62-73,122,136,158,203,218,274,304`; `format.ts:95-116`; `types.ts:7-15`).
- Do not change only `format.ts` constants or helpers to alter production wire format: crypto duplicates magic/version and record limits and maintains separate AD/framing code (`crypto.ts:23-25,55-73,114-117,146-149,188-191`; `format.ts:4-7,95-133`).
- Do not treat 1 MiB as plaintext chunk capacity or remove the `ABYTES` subtraction: the limit applies to ciphertext, prefixes store ciphertext length, and decrypt rejects larger records, so a 1 MiB plaintext record would reject its own output (`crypto.ts:23-25,120-121,146-149,196-201,294-296`).
- Do not omit the empty `TAG_FINAL` or remove the end-of-input abort check: both encrypt paths emit the final record, the async check prevents finalization after cancellation, and decrypt requires a final tag with an empty payload (`crypto.ts:155-172,216-232,316-327`).
- Do not treat `finalTagged = true` as parser termination: a subsequent complete record still reaches libsodium and a resulting `TAG_MESSAGE` may append plaintext; explicit parser-level terminal rejection is missing, while the existing test covers only a two-byte trailing fragment (`crypto.ts:278-327`; `crypto.test.ts:432-441`).
- Do not zero or mutate the caller key in decrypt error/finally cleanup: `decryptSync` uses it directly, and the regression test requires authentication failure to leave it unchanged (`crypto.ts:243-249,273,307-309`; `crypto.test.ts:167-177`).
- Do not advertise arbitrary range downloads as encrypted random access: S3 returns raw requested bytes, but decrypt requires the preamble and sequential secretstream state (`s3.ts:131-150`; `crypto.ts:251-305`).
- Do not describe multipart as streaming or part-size-bounded memory: streams are fully collected before routing and all part specs are built before workers, so lowering `minPartSize` or `concurrency` retains whole-object buffering (`s3.ts:96-118,250-260,475-484`).
- Do not remove the part-number sort before `CompleteMultipartUpload`: workers append results in network completion order, while assigned part numbers preserve data order (`s3.ts:251-256,283-290,353-372`).
- Do not assume `AbortSignal` cancels S3 I/O: signals are polled rather than passed to requests, `DownloadInput.signal` is unused by `download`, and multipart waits for its worker pool before cleanup; keep `safeAbortUpload` on cancellation because it deliberately ignores the signal and retries to avoid orphaned parts (`types.ts:35-60`; `s3.ts:91-110,124-158,223-235,278,296,332-366,380-403`).
- Do not treat one `.read() === null` as proven EOF for non-async-iterable Node bodies: the fallback ends immediately although null may mean temporarily no data, and the mock returns null only after draining, leaving temporary-null truncation behavior untested rather than observed (`s3.ts:449-466`; `s3.test.ts:470-488`).
