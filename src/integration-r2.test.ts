import { DeleteObjectCommand } from "@aws-sdk/client-s3";
import { beforeEach, describe, expect, it } from "vitest";
import { concat, decryptSync, encryptSync, initSodium } from "./crypto.js";
import { createR2Client, download, upload } from "./s3.js";

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET = process.env.R2_BUCKET;

describe("sdk-cloud R2 integration", () => {
  const credsOk = Boolean(R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET);
  const runIfCreds = credsOk ? it : it.skip;

  async function buffer(body: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of body) chunks.push(chunk);
    return concat(chunks);
  }

  let client: ReturnType<typeof createR2Client>;

  beforeEach(async () => {
    await initSodium();
    if (!R2_ACCOUNT_ID || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) return; // unreachable guard; TS narrows types below
    const account = R2_ACCOUNT_ID!;
    const accessKeyId = R2_ACCESS_KEY_ID!;
    const secretAccessKey = R2_SECRET_ACCESS_KEY!;
    client = createR2Client(
      account,
      { type: "static", accessKeyId, secretAccessKey },
      "auto",
      `https://${account}.r2.cloudflarestorage.com`,
    );
  });

  runIfCreds("upload and download small file through full pipeline", async () => {
    const data = new TextEncoder().encode("Hello from sdk-cloud R2 integration test!");
    const key = new Uint8Array(32);
    for (let i = 0; i < key.length; i++) key[i] = i;

    const { preamble, ciphertext } = encryptSync(data, key);
    const encrypted = concat([preamble, ciphertext]);
    const objectKey = `integration-test/small-${Date.now()}.enc`;

    // Upload
    const uploaded = await upload(client, {
      bucket: R2_BUCKET,
      key: objectKey,
      body: encrypted,
      contentType: "application/octet-stream",
    });
    expect(uploaded.key).toBe(objectKey);
    expect(uploaded.bucket).toBe(R2_BUCKET);
    expect(uploaded.etag).toBeTruthy();

    // Download
    const downloaded = await download(client, { bucket: R2_BUCKET, key: objectKey });
    const downloadedBytes = await buffer(downloaded.body);

    // Decrypt
    const result = decryptSync(downloadedBytes, key);
    expect(new TextDecoder().decode(result.plaintext)).toBe(
      "Hello from sdk-cloud R2 integration test!",
    );

    // Cleanup
    try {
      await client.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: objectKey }));
    } catch {
      /* ignore cleanup errors */
    }
  });

  runIfCreds("upload and download 1MB file", async () => {
    const dataSize = 1024 * 1024;
    const data = new Uint8Array(dataSize);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) % 256;

    const key = new Uint8Array(32);
    for (let i = 0; i < key.length; i++) key[i] = i;

    const { preamble, ciphertext } = encryptSync(data, key);
    const encrypted = concat([preamble, ciphertext]);
    const objectKey = `integration-test/1mb-${Date.now()}.enc`;

    const uploaded = await upload(client, {
      bucket: R2_BUCKET,
      key: objectKey,
      body: encrypted,
      contentType: "application/octet-stream",
    });
    expect(uploaded.etag).toBeTruthy();

    const downloaded = await download(client, { bucket: R2_BUCKET, key: objectKey });
    const downloadedBytes = await buffer(downloaded.body);

    const result = decryptSync(downloadedBytes, key);
    expect(result.plaintext).toEqual(data);
    expect(result.metadata.byteLength).toBe(BigInt(dataSize));

    try {
      await client.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: objectKey }));
    } catch {
      /* ignore cleanup errors */
    }
  });

  runIfCreds("presigned URL generation does not throw", async () => {
    const { createPresignedUploadUrl } = await import("./s3.js");
    const url = await createPresignedUploadUrl(client, {
      bucket: R2_BUCKET,
      key: `integration-test/presigned-${Date.now()}.enc`,
      body: new Uint8Array(0),
      contentType: "application/octet-stream",
    });

    expect(typeof url).toBe("string");
    expect(url.startsWith("https://")).toBe(true);
  });

  runIfCreds("multipart upload triggers for large-ish data (>5MB)", async () => {
    const largeData = new Uint8Array(6 * 1024 * 1024); // 6 MiB
    for (let i = 0; i < largeData.length; i++) largeData[i] = i % 256;

    const key = new Uint8Array(32);
    for (let i = 0; i < key.length; i++) key[i] = i;

    const { preamble, ciphertext } = encryptSync(largeData, key);
    const encrypted = concat([preamble, ciphertext]);

    const objectKey = `integration-test/multipart-${Date.now()}.enc`;

    const uploaded = await upload(client, {
      bucket: R2_BUCKET,
      key: objectKey,
      body: encrypted,
      contentType: "application/octet-stream",
    });
    expect(uploaded.etag).toBeTruthy();
    expect(uploaded.key).toBe(objectKey);

    // Verify by downloading and decrypting
    const downloaded = await download(client, { bucket: R2_BUCKET, key: objectKey });
    const downloadedBytes = await buffer(downloaded.body);
    const result = decryptSync(downloadedBytes, key);
    expect(result.plaintext).toEqual(largeData);
    expect(result.metadata.byteLength).toBe(BigInt(largeData.length));

    try {
      await client.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: objectKey }));
    } catch {
      /* ignore cleanup errors */
    }
  });
});
