import { setTimeout as sleep } from "node:timers/promises";
import { log } from "./cli.ts";

export type RetryOptions = {
  maxAttempts?: number;
  delayMs?: number;
  /**
   * explicit delay schedule — one entry per retry (length N ⇒ N+1 attempts).
   * when set, overrides `maxAttempts` and `delayMs`. e.g. `[1_000, 3_000]`
   * means up to 3 attempts, sleeping 1s before retry 2 and 3s before retry 3.
   */
  delaysMs?: readonly number[];
  shouldRetry?: (error: unknown) => boolean;
  label?: string;
};

const defaultShouldRetry = (error: unknown): boolean => {
  if (!(error instanceof Error)) return false;
  // retry on transient network errors
  return (
    error.name === "AbortError" ||
    error.message.includes("fetch failed") ||
    error.message.includes("ECONNRESET") ||
    error.message.includes("ETIMEDOUT")
  );
};

export async function retry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const shouldRetry = options.shouldRetry ?? defaultShouldRetry;
  const label = options.label ?? "operation";
  const delays = options.delaysMs
    ? Array.from(options.delaysMs)
    : Array.from(
        { length: (options.maxAttempts ?? 3) - 1 },
        (_, i) => (options.delayMs ?? 1000) * (i + 1),
      );
  const maxAttempts = delays.length + 1;

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      if (attempt === maxAttempts || !shouldRetry(error)) {
        throw error;
      }

      const delay = delays[attempt - 1]!;
      log.info(
        `» ${label} failed (attempt ${attempt}/${maxAttempts}), retrying in ${delay}ms...`,
      );
      await sleep(delay);
    }
  }

  throw lastError;
}
