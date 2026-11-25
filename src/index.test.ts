import { describe, expect, it } from "vitest";
import * as sdk from "./index.js";

describe("@shtora/s3poly public exports", () => {
  it("exports error classes", () => {
    expect(typeof sdk.AuthenticationError).toBe("function");
    expect(typeof sdk.FormatError).toBe("function");
    expect(typeof sdk.AbortError).toBe("function");
    expect(typeof sdk.StorageError).toBe("function");
  });

  it("exports crypto functions", () => {
    expect(typeof sdk.initSodium).toBe("function");
    expect(typeof sdk.isSodiumReady).toBe("function");
    expect(typeof sdk.encryptSync).toBe("function");
    expect(typeof sdk.decryptSync).toBe("function");
    expect(typeof sdk.getPreambleLength).toBe("function");
    expect(typeof sdk.getHeaderBytes).toBe("function");
    expect(typeof sdk.getAbytes).toBe("function");
    expect(typeof sdk.getTagMessage).toBe("function");
    expect(typeof sdk.getTagFinal).toBe("function");
    expect(typeof sdk.getKeyBytes).toBe("function");
  });

  it("exports format constants and utilities", () => {
    expect(sdk.PREAMBLE_MAGIC).toEqual(new Uint8Array([0x53, 0x4b, 0x44, 0x43]));
    expect(sdk.VERSION_V1).toBe(0x01);
    expect(sdk.LENGTH_PREFIX_SIZE).toBe(4);
    expect(typeof sdk.MAX_RECORD_BYTES).toBe("number");
    expect(typeof sdk.readPreamble).toBe("function");
    expect(typeof sdk.writePreamble).toBe("function");
    expect(typeof sdk.readRecord).toBe("function");
    expect(typeof sdk.buildRecordAd).toBe("function");
    expect(typeof sdk.encodeRecord).toBe("function");
  });

  it("exports S3 adapter functions", () => {
    expect(typeof sdk.createS3Client).toBe("function");
    expect(typeof sdk.upload).toBe("function");
    expect(typeof sdk.download).toBe("function");
    expect(typeof sdk.createPresignedUploadUrl).toBe("function");
    expect(typeof sdk.createPresignedDownloadUrl).toBe("function");
    expect(typeof sdk.createR2Client).toBe("function");
  });

  it("re-exported functions are the same references as the source modules", async () => {
    await sdk.initSodium();
    const key = new Uint8Array(sdk.getKeyBytes());
    for (let i = 0; i < key.length; i++) key[i] = i & 0xff;

    const data = new Uint8Array([0x0a, 0x0b, 0x0c]);
    const enc = sdk.encryptSync(data, key);
    const full = new Uint8Array(enc.preamble.length + enc.ciphertext.length);
    full.set(enc.preamble, 0);
    full.set(enc.ciphertext, enc.preamble.length);
    const dec = sdk.decryptSync(full, key);

    expect(dec.plaintext).toEqual(data);
  });

  it("MAX_RECORD_BYTES is exactly 1 MiB", () => {
    expect(sdk.MAX_RECORD_BYTES).toBe(1024 * 1024);
  });
});
