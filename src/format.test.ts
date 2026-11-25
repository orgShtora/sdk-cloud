import { beforeEach, describe, expect, it } from "vitest";
import { getHeaderBytes, getPreambleLength, initSodium } from "./crypto.js";
import {
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
import { FormatError } from "./types.js";

function makeHeader(length: number): Uint8Array {
  const h = new Uint8Array(length);
  for (let i = 0; i < h.length; i++) h[i] = i & 0xff;
  return h;
}

describe("@shtora/s3poly format", () => {
  beforeEach(async () => {
    await initSodium();
  });

  it("readPreamble returns valid structure for well-formed data", () => {
    const header = makeHeader(getHeaderBytes());
    const preamble = writePreamble(header);
    const encrypted = new Uint8Array(preamble.length + 8);
    encrypted.set(preamble, 0);
    encrypted.set([0, 0, 0, 8, 1, 2, 3, 4], preamble.length);

    const result = readPreamble(encrypted);
    expect(result.version).toBe(VERSION_V1);
    expect(result.header).toEqual(header);
    expect(result.rest.length).toBe(8);
  });

  it("readPreamble rejects too-short data", () => {
    const short = new Uint8Array([0x53, 0x4b, 0x44, 0x43, 0x01]);
    expect(() => readPreamble(short)).toThrow();
  });

  it("readPreamble rejects bad magic", () => {
    const header = makeHeader(getHeaderBytes());
    const preamble = writePreamble(header);
    const data = new Uint8Array(preamble.length + 4);
    data.set(preamble, 0);
    data[0] = 0x00;

    expect(() => readPreamble(data)).toThrow();
  });

  it("readPreamble rejects unsupported version", () => {
    const header = makeHeader(getHeaderBytes());
    const preamble = writePreamble(header);
    const data = new Uint8Array(preamble.length + 4);
    data.set(preamble, 0);
    data[4] = 0x02;

    expect(() => readPreamble(data)).toThrow();
  });

  it("writePreamble produces correct preamble bytes", () => {
    const header = makeHeader(getHeaderBytes());
    const preamble = writePreamble(header);

    expect(preamble.length).toBe(getPreambleLength());
    expect(preamble[0]).toBe(PREAMBLE_MAGIC[0]!);
    expect(preamble[1]).toBe(PREAMBLE_MAGIC[1]!);
    expect(preamble[2]).toBe(PREAMBLE_MAGIC[2]!);
    expect(preamble[3]).toBe(PREAMBLE_MAGIC[3]!);
    expect(preamble[4]).toBe(VERSION_V1);
    expect(preamble.subarray(5)).toEqual(header);
  });

  it("writePreamble rejects wrong header length", () => {
    const wrong = new Uint8Array(getHeaderBytes() + 1);
    expect(() => writePreamble(wrong)).toThrow();
  });

  it("encodeRecord prepends 4-byte BE length", () => {
    const ct = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const encoded = encodeRecord(ct);

    expect(encoded.length).toBe(LENGTH_PREFIX_SIZE + ct.length);
    expect(encoded[0]).toBe(0);
    expect(encoded[1]).toBe(0);
    expect(encoded[2]).toBe(0);
    expect(encoded[3]).toBe(3);
    expect(encoded.subarray(4)).toEqual(ct);
  });

  it("encodeRecord handles 0-length ciphertext", () => {
    const ct = new Uint8Array(0);
    const encoded = encodeRecord(ct);

    expect(encoded.length).toBe(LENGTH_PREFIX_SIZE);
    expect(encoded[0]).toBe(0);
    expect(encoded[1]).toBe(0);
    expect(encoded[2]).toBe(0);
    expect(encoded[3]).toBe(0);
  });

  it("encodeRecord handles max record bytes length boundary", () => {
    const ct = new Uint8Array(MAX_RECORD_BYTES);
    const encoded = encodeRecord(ct);
    expect(encoded.length).toBe(LENGTH_PREFIX_SIZE + MAX_RECORD_BYTES);
    expect(encoded[0]).toBe(0x00);
    expect(encoded[1]).toBe(0x10);
    expect(encoded[2]).toBe(0x00);
    expect(encoded[3]).toBe(0x00);
  });

  it("readRecord returns null for incomplete length prefix", () => {
    const data = new Uint8Array([0x00, 0x00, 0x01]);
    expect(readRecord(data, 0)).toBeNull();
  });

  it("readRecord returns null for incomplete record body", () => {
    const data = new Uint8Array([0x00, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05]);
    expect(readRecord(data, 0)).toBeNull();
  });

  it("readRecord parses multiple sequential records", () => {
    const ct1 = new Uint8Array([1, 2, 3]);
    const ct2 = new Uint8Array([4, 5, 6, 7]);

    const combined = new Uint8Array(
      LENGTH_PREFIX_SIZE + ct1.length + LENGTH_PREFIX_SIZE + ct2.length,
    );
    combined.set([0, 0, 0, ct1.length], 0);
    combined.set(ct1, LENGTH_PREFIX_SIZE);
    combined.set([0, 0, 0, ct2.length], LENGTH_PREFIX_SIZE + ct1.length);
    combined.set(ct2, LENGTH_PREFIX_SIZE + ct1.length + LENGTH_PREFIX_SIZE);

    const r1 = readRecord(combined, 0)!;
    expect(r1.length).toBe(ct1.length);
    expect(r1.ciphertext).toEqual(ct1);
    expect(r1.nextOffset).toBe(LENGTH_PREFIX_SIZE + ct1.length);

    const r2 = readRecord(combined, r1.nextOffset)!;
    expect(r2.length).toBe(ct2.length);
    expect(r2.ciphertext).toEqual(ct2);
    expect(r2.nextOffset).toBe(combined.length);
  });

  it("buildRecordAd includes preamble + position", () => {
    const header = makeHeader(getHeaderBytes());
    const preamble = writePreamble(header);
    const ad = buildRecordAd(preamble, 42n);

    expect(ad.length).toBe(getPreambleLength() + LENGTH_PREFIX_SIZE);
    expect(ad.subarray(0, getPreambleLength())).toEqual(preamble);

    expect(ad[getPreambleLength()]).toBe(0);
    expect(ad[getPreambleLength() + 1]).toBe(0);
    expect(ad[getPreambleLength() + 2]).toBe(0);
    expect(ad[getPreambleLength() + 3]).toBe(42);
  });

  it("buildRecordAd rejects wrong preamble length", () => {
    const shortPreamble = new Uint8Array(getPreambleLength() - 1);
    expect(() => buildRecordAd(shortPreamble, 0n)).toThrow();
  });

  it("full cycle: writePreamble -> readPreamble preserves all fields", () => {
    const originalHeader = makeHeader(getHeaderBytes());
    const preamble = writePreamble(originalHeader);
    const { version, header, rest } = readPreamble(preamble);

    expect(version).toBe(VERSION_V1);
    expect(header).toEqual(originalHeader);
    expect(rest.byteLength).toBe(0);
  });

  it("full cycle: encodeRecord -> readRecord roundtrips", () => {
    const originalCt = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
    const encoded = encodeRecord(originalCt);
    const decoded = readRecord(encoded, 0)!;

    expect(decoded.length).toBe(originalCt.length);
    expect(decoded.ciphertext).toEqual(originalCt);
    expect(decoded.nextOffset).toBe(encoded.length);
  });

  it("readRecord rejects lengths exceeding MAX_RECORD_BYTES", () => {
    const oversizedLen = MAX_RECORD_BYTES + 1;
    const data = new Uint8Array([
      (oversizedLen >> 24) & 0xff,
      (oversizedLen >> 16) & 0xff,
      (oversizedLen >> 8) & 0xff,
      oversizedLen & 0xff,
    ]);
    expect(() => readRecord(data, 0)).toThrow(FormatError);
  });

  it("readRecord returns null when ciphertext body is truncated mid-record", () => {
    const data = new Uint8Array([0x00, 0x00, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x05]);
    expect(readRecord(data, 0)).toBeNull();
  });
});
