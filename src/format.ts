import { getHeaderBytes, getPreambleLength } from "./crypto.js";
import { FormatError } from "./types.js";

export const PREAMBLE_MAGIC = new Uint8Array([0x53, 0x4b, 0x44, 0x43]);
export const VERSION_V1 = 0x01;
export const LENGTH_PREFIX_SIZE = 4;
export const MAX_RECORD_BYTES = 1024 * 1024;

export function readPreamble(data: Uint8Array): {
  version: number;
  header: Uint8Array;
  rest: Uint8Array;
} {
  const preambleLength = getPreambleLength();
  if (data.length < preambleLength) {
    throw new FormatError(
      `Insufficient data for preamble: expected at least ${preambleLength}, got ${data.length}`,
    );
  }

  // Validate magic
  for (let i = 0; i < 4; i++) {
    const expected = PREAMBLE_MAGIC[i]!;
    const actual = data[i]!;
    if (actual !== expected) {
      throw new FormatError(
        `Invalid preamble magic at offset ${i}: expected 0x${expected.toString(16)}, got 0x${actual.toString(16)}`,
      );
    }
  }

  const version = data[4]!;
  if (version !== VERSION_V1) {
    throw new FormatError(
      `Unsupported version: expected 0x${VERSION_V1.toString(16)}, got 0x${version.toString(16)}`,
    );
  }

  const header = data.subarray(5, preambleLength);
  const rest = data.subarray(preambleLength);

  return { version, header, rest };
}

/** Write the preamble to a buffer */
export function writePreamble(header: Uint8Array): Uint8Array {
  const headerBytes = getHeaderBytes();
  if (header.length !== headerBytes) {
    throw new FormatError(`Header must be ${headerBytes} bytes, got ${header.length}`);
  }

  const preambleLength = getPreambleLength();
  const preamble = new Uint8Array(preambleLength);
  preamble.set(PREAMBLE_MAGIC, 0);
  preamble[4] = VERSION_V1;
  preamble.set(header, 5);
  return preamble;
}

/** Read a single record from the data stream at the given offset. Returns bytes consumed. */
export function readRecord(
  data: Uint8Array,
  offset: number,
): { length: number; ciphertext: Uint8Array; nextOffset: number } | null {
  // Validate-before-read: inspect only the 4-byte length prefix before touching
  // anything else. An oversized value here must never trigger a large allocation.
  if (offset + LENGTH_PREFIX_SIZE > data.length) {
    return null; // Incomplete length prefix
  }

  const len0 = data[offset]!;
  const len1 = data[offset + 1]!;
  const len2 = data[offset + 2]!;
  const len3 = data[offset + 3]!;
  const length = ((len0 << 24) | (len1 << 16) | (len2 << 8) | len3) >>> 0;

  // Reject oversized records immediately without allocating. The spec mandates
  // validate-before-allocate; we throw rather than returning null because a
  // length > MAX_RECORD_BYTES signals corrupt/malicious input, not truncation.
  if (length > MAX_RECORD_BYTES) {
    throw new FormatError(`Record too large: ${length} bytes (max ${MAX_RECORD_BYTES})`);
  }

  if (offset + LENGTH_PREFIX_SIZE + length > data.length) {
    return null; // Incomplete record body
  }

  const ciphertext = data.subarray(
    offset + LENGTH_PREFIX_SIZE,
    offset + LENGTH_PREFIX_SIZE + length,
  );
  return { length, ciphertext, nextOffset: offset + LENGTH_PREFIX_SIZE + length };
}

/** Build the AD (additional authenticated data) for a record.
 * Layout: preamble || record plaintext position (uint32 BE).
 */
export function buildRecordAd(preamble: Uint8Array, position: bigint): Uint8Array {
  const preambleLength = getPreambleLength();
  if (preamble.length !== preambleLength) {
    throw new FormatError(`Preamble must be ${preambleLength} bytes, got ${preamble.length}`);
  }

  const ad = new Uint8Array(preambleLength + LENGTH_PREFIX_SIZE);
  ad.set(preamble, 0);
  // Position as big-endian uint32
  ad.set(
    [
      Number((position >> 24n) & 0xffn),
      Number((position >> 16n) & 0xffn),
      Number((position >> 8n) & 0xffn),
      Number(position & 0xffn),
    ],
    preamble.length,
  );
  return ad;
}

/** Encode a plaintext chunk into a length-prefixed record */
export function encodeRecord(ciphertext: Uint8Array): Uint8Array {
  const result = new Uint8Array(LENGTH_PREFIX_SIZE + ciphertext.length);
  result.set(
    [
      (ciphertext.length >>> 24) & 0xff,
      (ciphertext.length >>> 16) & 0xff,
      (ciphertext.length >>> 8) & 0xff,
      ciphertext.length & 0xff,
    ],
    0,
  );
  result.set(ciphertext, LENGTH_PREFIX_SIZE);
  return result;
}
