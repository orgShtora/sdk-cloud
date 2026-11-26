import sodium from "libsodium-wrappers";
import { nextWithSignal } from "./async.js";
import type { CryptoOptions, DecryptedMetadata } from "./types.js";
import { AbortError, AuthenticationError, FormatError } from "./types.js";
import {
  WIRE_LENGTH_PREFIX_SIZE,
  WIRE_MAGIC_BYTES,
  WIRE_MAX_RECORD_BYTES,
  WIRE_VERSION_V1,
} from "./wire.js";

let _headerBytes = 0;
let _keyBytes = 0;
let _abytes = 0;
let _tagMessage = 0;
let _tagFinal = 0;
let _preambleLength = 0;
let _maxRecordBytes = 0;
let _maxChunkBytes = 0;

export function initSodium(): Promise<void> {
  return sodium.ready.then(() => {
    _headerBytes = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    _keyBytes = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES;
    _abytes = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
    _tagMessage = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    _tagFinal = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    _preambleLength = 5 + _headerBytes;

    _maxRecordBytes = WIRE_MAX_RECORD_BYTES;

    _maxChunkBytes = _maxRecordBytes - _abytes;
  });
}

function ensureSodiumReady(): void {
  if (_keyBytes === 0) {
    throw new Error("libsodium is not initialized; call and await initSodium() first");
  }
}

function validateKeyLength(key: Uint8Array): void {
  if (key.length !== _keyBytes) {
    throw new RangeError(`Key must be ${_keyBytes} bytes`);
  }
}

export function isSodiumReady(): boolean {
  return _headerBytes > 0;
}
export function getPreambleLength(): number {
  return _preambleLength;
}
export function getHeaderBytes(): number {
  return _headerBytes;
}
export function getAbytes(): number {
  return _abytes;
}
export function getTagMessage(): number {
  return _tagMessage;
}
export function getTagFinal(): number {
  return _tagFinal;
}
export function getKeyBytes(): number {
  return _keyBytes;
}

function asUint8Array<T>(value: T): Uint8Array {
  return value as unknown as Uint8Array;
}

function writeU32BE(buf: Uint8Array, off: number, val: number): void {
  buf[off] = (val >>> 24) & 0xff;
  buf[off + 1] = (val >>> 16) & 0xff;
  buf[off + 2] = (val >>> 8) & 0xff;
  buf[off + 3] = val & 0xff;
}

function buildRecordAdWithCallerAd(
  preamble: Uint8Array,
  position: number,
  adBuf?: Uint8Array,
): Uint8Array {
  const baseLen = preamble.length;
  const callerAdLen = adBuf?.length ?? 0;
  const out = new Uint8Array(callerAdLen + baseLen + WIRE_LENGTH_PREFIX_SIZE);
  if (callerAdLen > 0) out.set(adBuf!, 0);
  out.set(preamble, callerAdLen);
  writeU32BE(out, callerAdLen + baseLen, position);
  return out;
}

export function concat(arrays: readonly Uint8Array[]): Uint8Array {
  if (arrays.length === 0) return new Uint8Array(0);
  if (arrays.length === 1 && arrays[0] !== undefined) return arrays[0];
  let total = 0;
  for (const a of arrays) if (a) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    if (a) {
      out.set(a, off);
      off += a.length;
    }
  }
  return out;
}

export async function* encrypt(
  input: AsyncIterable<Uint8Array>,
  options: CryptoOptions,
): AsyncGenerator<Uint8Array> {
  const requested = options.maxChunkSize;
  if (
    requested !== undefined &&
    (typeof requested !== "number" ||
      !Number.isFinite(requested) ||
      !Number.isInteger(requested) ||
      requested <= 0)
  ) {
    throw new RangeError("maxChunkSize must be a positive integer");
  }

  await initSodium();
  const key = await options.keyProvider.generateKey();
  validateKeyLength(key);

  const pushResult = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const state = pushResult.state;
  const header = asUint8Array(pushResult.header);

  const preamble = new Uint8Array(_preambleLength);
  preamble.set(WIRE_MAGIC_BYTES, 0);
  preamble[4] = WIRE_VERSION_V1;
  preamble.set(header, 5);
  yield preamble;

  const maxChunkSize =
    requested === undefined ? _maxChunkBytes : Math.min(requested, _maxChunkBytes);
  const ad = options.ad;
  let position = 0;

  const iterator = input[Symbol.asyncIterator]();
  let completed = false;
  try {
    while (true) {
      const next = await nextWithSignal(iterator, options.signal);
      if (next.done) {
        completed = true;
        break;
      }
      const chunk = next.value;
      if (options.signal?.aborted) throw new AbortError();

      let offset = 0;
      while (offset < chunk.length) {
        if (options.signal?.aborted) throw new AbortError();

        const remaining = chunk.length - offset;
        const take = Math.min(remaining, maxChunkSize);
        const msg = chunk.subarray(offset, offset + take);

        const recordAd = buildRecordAdWithCallerAd(preamble, position, ad);
        const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
          state,
          msg,
          recordAd,
          _tagMessage,
        );
        if (!ct) throw new AuthenticationError("Encryption push returned null");

        const ctArr = asUint8Array(ct);
        const lenPrefix = new Uint8Array(WIRE_LENGTH_PREFIX_SIZE + ctArr.length);
        writeU32BE(lenPrefix, 0, ctArr.length);
        lenPrefix.set(ctArr, WIRE_LENGTH_PREFIX_SIZE);
        yield lenPrefix;
        position += msg.length;
        offset += take;
      }
    }
  } finally {
    if (!completed) {
      void Promise.resolve(iterator.return?.()).catch(() => undefined);
    }
  }

  if (options.signal?.aborted) throw new AbortError();

  {
    const recordAd = buildRecordAdWithCallerAd(preamble, position, ad);
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array(0),
      recordAd,
      _tagFinal,
    );
    if (!ct) throw new AuthenticationError("TAG_FINAL push returned null");

    const ctArr = asUint8Array(ct);
    const lenPrefix = new Uint8Array(WIRE_LENGTH_PREFIX_SIZE + ctArr.length);
    writeU32BE(lenPrefix, 0, ctArr.length);
    lenPrefix.set(ctArr, WIRE_LENGTH_PREFIX_SIZE);
    yield lenPrefix;
  }
}

export function encryptSync(
  data: Uint8Array,
  key: Uint8Array,
  ad?: Uint8Array,
): { preamble: Uint8Array; ciphertext: Uint8Array } {
  ensureSodiumReady();
  validateKeyLength(key);

  const pushResult = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const state = pushResult.state;
  const header = asUint8Array(pushResult.header);

  const preamble = new Uint8Array(_preambleLength);
  preamble.set(WIRE_MAGIC_BYTES, 0);
  preamble[4] = WIRE_VERSION_V1;
  preamble.set(header, 5);

  const allChunks: Uint8Array[] = [];
  let position = 0;
  let offset = 0;
  const maxChunkSize = _maxChunkBytes;

  // Process all data chunks with TAG_MESSAGE
  while (offset < data.length) {
    const remaining = data.length - offset;
    const take = Math.min(remaining, maxChunkSize);
    const msg = data.subarray(offset, offset + take);
    const recordAd = buildRecordAdWithCallerAd(preamble, position, ad);
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(state, msg, recordAd, _tagMessage);
    if (!ct) throw new AuthenticationError("Encryption push failed");

    const ctArr = asUint8Array(ct);
    const lenPrefix = new Uint8Array(WIRE_LENGTH_PREFIX_SIZE + ctArr.length);
    writeU32BE(lenPrefix, 0, ctArr.length);
    lenPrefix.set(ctArr, WIRE_LENGTH_PREFIX_SIZE);
    allChunks.push(lenPrefix);
    position += msg.length;
    offset += take;
  }

  // Always emit explicit empty-message TAG_FINAL
  {
    const recordAd = buildRecordAdWithCallerAd(preamble, position, ad);
    const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      new Uint8Array(0),
      recordAd,
      _tagFinal,
    );
    if (!ct) throw new AuthenticationError("TAG_FINAL push failed");

    const ctArr = asUint8Array(ct);
    const lenPrefix = new Uint8Array(WIRE_LENGTH_PREFIX_SIZE + ctArr.length);
    writeU32BE(lenPrefix, 0, ctArr.length);
    lenPrefix.set(ctArr, WIRE_LENGTH_PREFIX_SIZE);
    allChunks.push(lenPrefix);
  }

  return { preamble, ciphertext: concat(allChunks) };
}

// ─── Sync decrypt ─────────────────────────────────────────────────────────────

/**
 * Decrypt V1 format bytes synchronously.
 * encrypted = preamble || (lenPrefix || ciphertext)*
 */
export function decryptSync(
  encrypted: Uint8Array,
  key: Uint8Array,
  ad?: Uint8Array,
): { plaintext: Uint8Array; metadata: DecryptedMetadata } {
  ensureSodiumReady();
  validateKeyLength(key);
  if (encrypted.length < _preambleLength) {
    throw new FormatError("Encrypted data too short for preamble");
  }

  for (let i = 0; i < WIRE_MAGIC_BYTES.length; i++) {
    if (encrypted[i] !== WIRE_MAGIC_BYTES[i]) {
      throw new FormatError("Invalid preamble: expected SKDC");
    }
  }
  if (encrypted[4] !== WIRE_VERSION_V1) {
    throw new FormatError(
      `Unsupported version: expected 0x${WIRE_VERSION_V1.toString(16)}, got 0x${encrypted[4]!.toString(16)}`,
    );
  }

  const preamble = encrypted.subarray(0, _preambleLength);
  const header = encrypted.subarray(5, _preambleLength) as Uint8Array;
  const rest = encrypted.subarray(_preambleLength);

  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  const adBuf = ad;
  const plaintextChunks: Uint8Array[] = [];
  let position = 0;
  let offset = 0;
  let finalTagged = false;

  while (offset < rest.length) {
    if (finalTagged) throw new FormatError("Trailing bytes after TAG_FINAL");
    if (offset + WIRE_LENGTH_PREFIX_SIZE > rest.length) {
      throw new FormatError("Truncated length prefix before TAG_FINAL");
    }

    const len =
      ((rest[offset]! << 24) |
        (rest[offset + 1]! << 16) |
        (rest[offset + 2]! << 8) |
        rest[offset + 3]!) >>>
      0;
    offset += WIRE_LENGTH_PREFIX_SIZE;

    if (len > _maxRecordBytes) {
      throw new FormatError(`Record too large: ${len} bytes`);
    }
    if (offset + len > rest.length) {
      throw new FormatError("Truncated ciphertext record");
    }

    const record = rest.subarray(offset, offset + len);
    offset += len;

    const recordAd = buildRecordAdWithCallerAd(preamble, position, adBuf);
    const result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, record, recordAd);

    if (result === false || result === null) {
      throw new AuthenticationError("Authentication failed: tampered or corrupted data");
    }

    const { message, tag } = result as { message: Uint8Array; tag: number };

    if (tag === _tagMessage) {
      plaintextChunks.push(message);
      position += message.length;
    } else if (tag === _tagFinal) {
      if (message.length !== 0) {
        throw new FormatError("TAG_FINAL must contain empty message");
      }
      finalTagged = true;
    } else {
      throw new FormatError(`Unexpected tag: ${tag}`);
    }
  }

  if (!finalTagged) throw new FormatError("Missing authenticated TAG_FINAL");
  if (offset < rest.length) throw new FormatError("Trailing bytes after TAG_FINAL");

  const plaintext = concat(plaintextChunks);
  return {
    plaintext,
    metadata: { byteLength: BigInt(plaintext.length), preamble },
  };
}
