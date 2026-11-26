# @shtora/s3poly

## OVERVIEW

- The package provides libsodium secretstream encryption and S3-compatible transport helpers. Call `encrypt` before `upload` to store ciphertext.
- The default test, watch, coverage, and prepublish paths select the four offline suites. Live R2 operations run only through the integration script.
- See src/AGENTS.md for wire-format, crypto, multipart, and cancellation invariants.

## WHERE TO LOOK

| Need | Start here |
| --- | --- |
| Script selection and release flow | package.json scripts |
| Discovery and coverage policy | vitest.config.ts |
| Wire framing and authenticated records | src/wire.ts, src/format.ts, src/crypto.ts |
| S3 upload, multipart, cancellation, and downloads | src/s3.ts, src/types.ts |
| R2 integration and cleanup | src/integration-r2.test.ts |

## CONVENTIONS

- package scripts name offline test files explicitly. The integration script requires all four R2 variables and fails fast when any are absent.
- Coverage measures all non-test src TypeScript and keeps the configured 90% line/function/statement and 85% branch thresholds.
- R2 tests use network access and an existing bucket. Test objects are tracked and best-effort deleted in afterEach.
- Script and declaration counts describe selected test cases, not observed pass/fail outcomes.

## ANTI-PATTERNS

- Do not treat direct Vitest discovery as offline: the R2 file is discovered by the global include pattern and requires credentials. Use bun run test for the offline suites.
- Do not treat test:integration as a credentials provider or offline check. It performs real operations against the configured account and bucket.
- Do not assume integration cleanup can remove objects after a service-side delete failure; cleanup is best-effort.
- Streamed uploads use bounded multipart buffers; their maximum size is limited by `minPartSize * 10,000` (capped at 5 TiB). `decryptSync` still holds the full ciphertext and plaintext in memory.
- Do not report static test declarations as passes without executing a test command.
