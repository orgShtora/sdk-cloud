import { AbortError } from "./types.js";

/** Wait for the next item or abort; the consumer owns iterator cleanup. */
export async function nextWithSignal<T>(
  iterator: AsyncIterator<T>,
  signal?: AbortSignal,
): Promise<IteratorResult<T>> {
  if (!signal) return await iterator.next();
  if (signal.aborted) throw new AbortError();

  let onAbort = () => {};
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => {
      reject(new AbortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });

  try {
    return await Promise.race([iterator.next(), aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}
