# sdk-cloud

## OVERVIEW

- Operational scope: Vitest selection, coverage, offline suites, and credential-gated R2 side effects (`package.json:21-30`, `vitest.config.ts:3-19`, `src/integration-r2.test.ts:6-37`).
- See [src/AGENTS.md](src/AGENTS.md) for implementation contracts and invariants.

## WHERE TO LOOK

| Need | Start here |
| --- | --- |
| Script selection and release flow | `package.json:21-30` — default/watch/coverage/integration/unit selection and the prepublish test path. |
| Discovery and coverage policy | `vitest.config.ts:3-19` — test glob, globals, V8 reporters, source scope, and thresholds. |
| Crypto initialization and cost | `src/crypto.test.ts:26-136,180-188` — 32 declarations, sodium setup, 10 MiB stress, and two 1 MiB cases. |
| Format initialization and fixtures | `src/format.test.ts:16-203` — 18 declarations, sodium setup, and generated in-memory inputs. |
| Public-surface smoke declarations | `src/index.test.ts:4-64` — six declarations; one performs a small roundtrip. |
| Mocked S3 behavior and cost | `src/s3.test.ts:22-73,128-162,616-634` — 41 declarations, module mocks, large bodies, and abort retries. |
| Live R2 gating and object lifecycle | `src/integration-r2.test.ts:6-35,37-155` — four gated declarations, real operations, presign-only coverage, and cleanup placement. |

## CONVENTIONS

- Discovery uses `src/**/*.test.ts` with globals enabled; no setup/global-setup files or project-level discovery exclusion are configured (`vitest.config.ts:3-6`).
- Coverage is opt-in V8 with text/JSON/HTML reporters; it measures `src/**/*.ts`, excludes tests, and requires 90% lines/functions/statements plus 85% branches; no coverage artifacts or measured percentages are present (`vitest.config.ts:7-18`).
- Crypto and format initialize sodium in `beforeEach` and build inline inputs without disk fixtures; S3 mocks clients/commands/signing at module scope and needs no live service (`src/crypto.test.ts:26-29`, `src/format.test.ts:22-25`, `src/s3.test.ts:22-54`).
- Static inventory is 101 declarations: crypto 32, format 18, index 6, S3 41, and R2 4; 97 are unconditional and four credential-gated, not observed pass/fail counts (`src/crypto.test.ts:26-526`, `src/format.test.ts:22-203`, `src/index.test.ts:4-64`, `src/s3.test.ts:70-635`, `src/integration-r2.test.ts:11-155`).

## ANTI-PATTERNS

- Do not treat `test:unit` as unit-only: its `src/*.test.ts` selection also matches `src/integration-r2.test.ts`; default, watch, coverage, and prepublish test paths discover that file too (`package.json:24-30`, `vitest.config.ts:5`).
- Do not expect `test:integration` to provide credentials or force execution; four R2 variables are captured once during collection and all must be truthy or `it.skip` is selected, with no CI/`RUN_INTEGRATION`/endpoint/per-test alternate gate (`package.json:27`, `src/integration-r2.test.ts:6-13,37-155`).
- Do not assume credentialed runs are offline: the suite targets `https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com` in region `auto`, requiring network, an existing accessible bucket, and operation permissions; it does not create/delete the bucket (`src/integration-r2.test.ts:23-35,37-155`).
- Do not ignore watch amplification: with all four credentials, reruns repeat small, 1 MiB, and 6 MiB multipart roundtrips; presigned PUT coverage generates a URL only and does not explicitly send an object (`package.json:25`, `src/integration-r2.test.ts:37-155`).
- Do not rely on failure cleanup: three uploading cases delete only after all operations/assertions succeed, cleanup is best-effort with ignored errors, and no `finally`/after-hook/stale-object sweep exists (`src/integration-r2.test.ts:37-73,75-107,122-155`).
- Do not add or infer snapshot infrastructure: no snapshot APIs/serializers or snapshot artifacts are present; the `snapshot` variable in the key-preservation regression is only a copied key (`src/crypto.test.ts:167-178`).
- Do not expect focused coverage to relax thresholds: selecting one suite still measures all included non-test source, so unexercised files can fail global thresholds (`vitest.config.ts:7-18`).
- Do not mistake mocked suites for cheap runs: always-on crypto cases allocate 10 MiB and two 1 MiB payloads, S3 allocates 12 MiB and 30 MiB bodies, and the all-abort-fail case incurs real 100 ms + 200 ms backoff without fake timers (`src/crypto.test.ts:84-136,180-188`, `src/s3.test.ts:128-162,616-634`, `src/s3.ts:386-407`).
- Do not report the 101 declarations as 101 passes or four skips as an observed outcome; declaration/gating analysis is static and no tests, builds, or integration operations were run for this document (`src/index.test.ts:4-64`, `src/integration-r2.test.ts:11-13`).
