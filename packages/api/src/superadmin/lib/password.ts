/**
 * Super-admin password hashing: PBKDF2-SHA256 with a per-password random salt.
 * Stored as `pbkdf2_sha256$<iterations>$<salt b64>$<hash b64>`. Runs on Workers and Node.
 */

const ALGORITHM = "pbkdf2_sha256";
const ITERATIONS = 100_000; // Workers' PBKDF2 ceiling
const SALT_BYTES = 16;
const HASH_BYTES = 32;

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (ch) => ch.charCodeAt(0));
}

async function derive(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    HASH_BYTES * 8
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const hash = await derive(password, salt, ITERATIONS);
  return `${ALGORITHM}$${ITERATIONS}$${toBase64(salt)}$${toBase64(hash)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [algorithm, iterationsRaw, saltB64, hashB64] = stored.split("$");
  const iterations = Number(iterationsRaw);
  if (algorithm !== ALGORITHM || !Number.isInteger(iterations) || iterations < 1 || iterations > ITERATIONS) {
    return false;
  }
  let salt: Uint8Array<ArrayBuffer>;
  let expected: Uint8Array;
  try {
    salt = fromBase64(saltB64);
    expected = fromBase64(hashB64);
  } catch {
    return false;
  }
  const actual = await derive(password, salt, iterations);
  if (actual.length !== expected.length) return false;
  // Constant-time compare.
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

// Verified against when the email is unknown, so response time doesn't reveal which emails exist.
let dummyHash: Promise<string> | null = null;
export function getDummyHash(): Promise<string> {
  dummyHash ??= hashPassword(crypto.randomUUID());
  return dummyHash;
}
