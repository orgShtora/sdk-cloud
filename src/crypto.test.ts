import sodium from "libsodium-wrappers";
import { beforeEach, describe, expect, it } from "vitest";
import {
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
import { buildRecordAd, encodeRecord, writePreamble } from "./format.js";
import { AbortError, AuthenticationError, FormatError } from "./types.js";

function makeKey(): Uint8Array {
  const key = new Uint8Array(getKeyBytes());
  for (let i = 0; i < key.length; i++) key[i] = i & 0xff;
  return key;
}

describe("sdk-cloud crypto", () => {
  beforeEach(async () => {
    await initSodium();
  });

  it("crypto constants match libsodium runtime values", () => {
    expect(getPreambleLength()).toBe(5 + getHeaderBytes());
    expect(getHeaderBytes()).toBe(sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES);
    expect(getKeyBytes()).toBe(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES);
    expect(getAbytes()).toBe(sodium.crypto_secretstream_xchacha20poly1305_ABYTES);
    expect(getTagMessage()).toBe(sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
    expect(getTagFinal()).toBe(sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
    expect(isSodiumReady()).toBe(true);
  });

  it("encryptSync / decryptSync empty data roundtrip", () => {
    const key = makeKey();
    const result = encryptSync(new Uint8Array(0), key);
    expect(result.preamble.length).toBe(getPreambleLength());
    expect(result.ciphertext.length).toBe(4 + getAbytes());

    const encrypted = concat([result.preamble, result.ciphertext]);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(new Uint8Array(0));
    expect(decrypted.metadata.byteLength).toBe(0n);
  });

  it("encryptSync / decryptSync single byte", () => {
    const key = makeKey();
    const data = new Uint8Array([0x42]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(data);
    expect(decrypted.metadata.byteLength).toBe(1n);
  });

  it("encryptSync / decryptSync 5 bytes", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(data);
    expect(decrypted.metadata.byteLength).toBe(5n);
  });

  it("encryptSync / decryptSync 1 KiB chunked by internal buffer", () => {
    const key = makeKey();
    const data = new Uint8Array(1024);
    for (let i = 0; i < data.length; i++) data[i] = i % 256;
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(data);
    expect(decrypted.metadata.byteLength).toBe(BigInt(data.length));
  });

  it("encryptSync / decryptSync 1 MiB (multi-record)", async () => {
    const key = makeKey();
    const size = 1024 * 1024;
    const data = new Uint8Array(size);
    for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) % 256;

    const keyProvider = {
      generateKey: async () => key,
      resolveKey: async () => key,
    };
    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield data;
    })();

    const yielded: Uint8Array[] = [];
    for await (const part of encrypt(chunks, { keyProvider, maxChunkSize: 256 * 1024 })) {
      yielded.push(part);
    }

    expect(yielded.length).toBe(6);

    const encrypted = concat(yielded);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(data);
    expect(decrypted.metadata.byteLength).toBe(BigInt(size));
  });

  it("encryptSync / decryptSync 10 MiB (stress)", async () => {
    const key = makeKey();
    const size = 10 * 1024 * 1024;
    const data = new Uint8Array(size);
    for (let i = 0; i < data.length; i++) data[i] = (i * 13 + 7) % 256;

    const keyProvider = {
      generateKey: async () => key,
      resolveKey: async () => key,
    };
    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield data;
    })();

    const yielded: Uint8Array[] = [];
    for await (const part of encrypt(chunks, { keyProvider, maxChunkSize: 256 * 1024 })) {
      yielded.push(part);
    }

    expect(yielded.length).toBe(42);

    const encrypted = concat(yielded);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(data);
    expect(decrypted.metadata.byteLength).toBe(BigInt(size));
  });

  it("AD binding works bidirectionally", () => {
    const key = makeKey();
    const ad = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const data = new Uint8Array([0xaa, 0xbb, 0xcc]);

    const result = encryptSync(data, key, ad);
    const encrypted = concat([result.preamble, result.ciphertext]);

    const decrypted = decryptSync(encrypted, key, ad);
    expect(decrypted.plaintext).toEqual(data);

    const wrongAd = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    expect(() => decryptSync(encrypted, key, wrongAd)).toThrow(AuthenticationError);
  });

  it("reject tampered ciphertext", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    if (encrypted.length > 0) {
      const lastIdx = encrypted.length - 1;
      encrypted[lastIdx]! ^= 0xff;
    }

    expect(() => decryptSync(encrypted, key)).toThrow(AuthenticationError);
  });

  it("does not zero the caller key on a tampered-decrypt failure (B1 regression)", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    encrypted[encrypted.length - 1]! ^= 0xff;

    const snapshot = new Uint8Array(key);
    expect(() => decryptSync(encrypted, key)).toThrow(AuthenticationError);
    expect(key).toEqual(snapshot);
  });

  it("roundtrips exactly 1 MiB without exceeding MAX_RECORD_BYTES (B2 regression)", () => {
    const key = makeKey();
    const data = new Uint8Array(1024 * 1024);
    for (let i = 0; i < data.length; i++) data[i] = i % 256;
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);
    const decrypted = decryptSync(encrypted, key);
    expect(decrypted.plaintext).toEqual(data);
  });

  it("reject truncated preamble", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    const preambleLen = getPreambleLength();
    const truncated = encrypted.subarray(0, preambleLen - 1);
    expect(() => decryptSync(truncated, key)).toThrow(FormatError);
  });

  it("reject wrong version byte", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    encrypted[4] = 0x02;
    expect(() => decryptSync(encrypted, key)).toThrow(FormatError);
  });

  it("reject invalid magic", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    encrypted[0] = 0x00;
    expect(() => decryptSync(encrypted, key)).toThrow(FormatError);
  });

  it("reject truncated record length prefix", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    const preambleLen = getPreambleLength();
    const cut = Math.max(preambleLen + 1, encrypted.length - 2);
    const truncated = encrypted.subarray(0, cut);
    expect(() => decryptSync(truncated, key)).toThrow(FormatError);
  });

  it("reject oversized record length", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01]);
    const result = encryptSync(data, key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    const preambleLen = getPreambleLength();
    const offset = preambleLen;

    const oversizedPrefix = new Uint8Array([0x10, 0x00, 0x00, 0x00]);
    encrypted.set(oversizedPrefix, offset);

    expect(() => decryptSync(encrypted, key)).toThrow(FormatError);
  });

  it("async encrypt yields preamble then records", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const data = new Uint8Array([0xab, 0xcd, 0xef, 0x01, 0x02]);

    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield data;
    })();

    const yielded: Uint8Array[] = [];
    for await (const part of encrypt(chunks, {
      keyProvider: {
        generateKey: async () => key,
        resolveKey: async () => key,
      },
    })) {
      yielded.push(part);
    }

    expect(yielded.length).toBeGreaterThanOrEqual(2);
    expect(yielded[0]!.length).toBe(getPreambleLength());
    expect(yielded[0]![0]).toBe(0x53);
    expect(yielded[0]![1]).toBe(0x4b);
    expect(yielded[0]![2]).toBe(0x44);
    expect(yielded[0]![3]).toBe(0x43);
    expect(yielded[0]![4]).toBe(0x01);

    for (let i = 1; i < yielded.length; i++) {
      const rec = yielded[i]!;
      expect(rec.length).toBeGreaterThan(4);
    }
  });

  it("async encrypt aborts mid-stream", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const controller = new AbortController();

    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield new Uint8Array(1024);
      controller.abort();
      yield new Uint8Array(1024);
    })();

    const gen = encrypt(chunks, {
      keyProvider: {
        generateKey: async () => key,
        resolveKey: async () => key,
      },
      signal: controller.signal,
    });

    let threw = false;
    for (let i = 0; i < 10; i++) {
      try {
        const n = await gen.next();
        if (n.done) break;
      } catch (e) {
        expect(e).toBeInstanceOf(AbortError);
        threw = true;
        break;
      }
    }
    expect(threw).toBe(true);
  });

  it("async encrypt empty stream", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();

    const chunks: AsyncIterable<Uint8Array> = (async function* () {})();

    const yielded: Uint8Array[] = [];
    for await (const part of encrypt(chunks, {
      keyProvider: {
        generateKey: async () => key,
        resolveKey: async () => key,
      },
    })) {
      yielded.push(part);
    }

    expect(yielded.length).toBe(2);
    expect(yielded[0]!.length).toBe(getPreambleLength());
  });

  it("encrypt rejects an invalid maxChunkSize before doing any work", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield new Uint8Array(16);
    })();

    const bad: Array<number | undefined> = [0, -1, NaN, Infinity, -Infinity, 1.5];
    for (const maxChunkSize of bad) {
      await expect(
        (async () => {
          for await (const _ of encrypt(chunks, {
            keyProvider: { generateKey: async () => key, resolveKey: async () => key },
            maxChunkSize,
          })) {
          }
        })(),
      ).rejects.toThrow(RangeError);
    }
  });

  it("encrypt clamps a maxChunkSize larger than the 1 MiB record cap", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const data = new Uint8Array(3000);
    for (let i = 0; i < data.length; i++) data[i] = i & 0xff;
    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield data;
    })();

    const yielded: Uint8Array[] = [];
    for await (const part of encrypt(chunks, {
      keyProvider: { generateKey: async () => key, resolveKey: async () => key },
      maxChunkSize: 10 * 1024 * 1024,
    })) {
      yielded.push(part);
    }

    expect(yielded.length).toBe(3);

    const encrypted = concat(yielded);
    const dec = decryptSync(encrypted, key);
    expect(dec.plaintext).toEqual(data);
  });

  it("encrypt raises AbortError when the signal aborts at end of input (before TAG_FINAL)", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const controller = new AbortController();

    const chunks: AsyncIterable<Uint8Array> = (async function* () {
      yield new Uint8Array(16);
      controller.abort();
    })();

    const yielded: Uint8Array[] = [];
    await expect(
      (async () => {
        for await (const part of encrypt(chunks, {
          keyProvider: { generateKey: async () => key, resolveKey: async () => key },
          signal: controller.signal,
        })) {
          yielded.push(part);
        }
      })(),
    ).rejects.toThrow(AbortError);

    expect(yielded.length).toBe(2);
  });

  it("key too short rejects with Error", () => {
    const key = new Uint8Array(getKeyBytes() - 1);
    expect(() => encryptSync(new Uint8Array([1]), key)).toThrow(Error);
  });

  it("key too long rejects with Error", () => {
    const key = new Uint8Array(getKeyBytes() + 1);
    expect(() => encryptSync(new Uint8Array([1]), key)).toThrow(Error);
  });

  it("encrypted output is non-deterministic (different headers each run)", () => {
    const key = makeKey();
    const data = new Uint8Array([0x01, 0x02, 0x03]);

    const r1 = encryptSync(data, key);
    const r2 = encryptSync(data, key);

    expect(r1.preamble).not.toEqual(r2.preamble);

    expect(r1.preamble.length).toBe(r2.preamble.length);
    expect(r1.preamble.length).toBe(getPreambleLength());
  });

  it("decryptSync rejects a wrong-length key", () => {
    const key = makeKey();
    const result = encryptSync(new Uint8Array([0x01]), key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    const shortKey = new Uint8Array(getKeyBytes() - 1);
    const longKey = new Uint8Array(getKeyBytes() + 1);
    expect(() => decryptSync(encrypted, shortKey)).toThrow(Error);
    expect(() => decryptSync(encrypted, longKey)).toThrow(Error);
  });

  it("decryptSync rejects trailing partial length prefix after TAG_FINAL", () => {
    const key = makeKey();
    const result = encryptSync(new Uint8Array([0x01, 0x02, 0x03]), key);
    const encrypted = concat([result.preamble, result.ciphertext]);

    const trailing = new Uint8Array(encrypted.length + 2);
    trailing.set(encrypted, 0);
    trailing.set([0xaa, 0xbb], encrypted.length);

    expect(() => decryptSync(trailing, key)).toThrow(FormatError);
  });

  it("format module: encodeRecord + buildRecordAd wire into a valid record AD", () => {
    const preamble = new Uint8Array(getPreambleLength());
    preamble.set([0x53, 0x4b, 0x44, 0x43], 0);
    preamble[4] = 0x01;
    const record = encodeRecord(new Uint8Array([9, 8, 7]));
    const ad = buildRecordAd(preamble, 3n);

    expect(ad[0]).toBe(0x53);
    expect(ad[preamble.length]).toBe(0);
    expect(ad[preamble.length + 3]).toBe(3);

    expect(record[0]).toBe(0);
    expect(record[3]).toBe(3);
  });

  it("encrypt over an empty iterable with an already-aborted signal fails", async () => {
    const key = await sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const controller = new AbortController();
    controller.abort();
    const empty: AsyncIterable<Uint8Array> = (async function* () {})();

    const yielded: Uint8Array[] = [];
    await expect(
      (async () => {
        for await (const part of encrypt(empty, {
          keyProvider: { generateKey: async () => key, resolveKey: async () => key },
          signal: controller.signal,
        })) {
          yielded.push(part);
        }
      })(),
    ).rejects.toThrow(AbortError);
    expect(yielded.length).toBe(1);
  });

  it("decryptSync rejects an unexpected stream tag", () => {
    const key = makeKey();
    const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    const preamble = writePreamble(header as Uint8Array);
    const ad = buildRecordAd(preamble, 0n);
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array([1]),
      ad,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    );
    const body = encodeRecord(ct);
    const full = concat([preamble, body]);
    expect(() => decryptSync(full, key)).toThrow(FormatError);
  });

  it("decryptSync rejects a TAG_FINAL carrying non-empty payload", () => {
    const key = makeKey();
    const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    const preamble = writePreamble(header as Uint8Array);
    const ad = buildRecordAd(preamble, 0n);
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array([1]),
      ad,
      getTagFinal(),
    );
    const body = encodeRecord(ct);
    const full = concat([preamble, body]);
    expect(() => decryptSync(full, key)).toThrow(FormatError);
  });

  it("decryptSync rejects a stream with only TAG_MESSAGE and no TAG_FINAL", () => {
    const key = makeKey();
    const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    const preamble = writePreamble(header as Uint8Array);
    const ad = buildRecordAd(preamble, 0n);
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array([1]),
      ad,
      getTagMessage(),
    );
    const body = encodeRecord(ct);
    const full = concat([preamble, body]);
    expect(() => decryptSync(full, key)).toThrow(FormatError);
  });
});
