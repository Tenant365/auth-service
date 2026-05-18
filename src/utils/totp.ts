const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateBase32Secret(size = 20): string {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  let result = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += BASE32_ALPHABET[(value >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return result;
}

export function base32Decode(encoded: string): Uint8Array {
  const cleaned = encoded.toUpperCase().replace(/\s|=/g, "");
  const result: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error(`Invalid base32 character: ${char}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      result.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}

async function hmacSha1(secretBytes: Uint8Array, counter: bigint): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, counter, false);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
}

async function generateHOTP(secretBytes: Uint8Array, counter: bigint): Promise<number> {
  const mac = await hmacSha1(secretBytes, counter);
  const offset = mac[19] & 0xf;
  const code =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return code % 1_000_000;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function verifyTOTP(secret: string, token: string, window = 1): Promise<boolean> {
  const T = BigInt(Math.floor(Date.now() / 1000 / 30));
  const secretBytes = base32Decode(secret);
  const normalized = token.replace(/\s/g, "");
  for (let i = -window; i <= window; i++) {
    const code = (await generateHOTP(secretBytes, T + BigInt(i))).toString().padStart(6, "0");
    if (timingSafeEqual(normalized, code)) return true;
  }
  return false;
}

export function buildTotpUri(secret: string, email: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: "6", period: "30" });
  return `otpauth://totp/${label}?${params}`;
}

const BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generateBackupCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = "";
  for (const b of bytes) code += BACKUP_ALPHABET[b % BACKUP_ALPHABET.length];
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

export async function sha256Hex(value: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function verifySha256(value: string, hex: string): Promise<boolean> {
  return timingSafeEqual(await sha256Hex(value), hex);
}

export function generateRandomHex(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function encodeHandle(jti: string, token: string): string {
  const bytes = new TextEncoder().encode(`${jti}:${token}`);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeHandle(handle: string): { jti: string; token: string } | null {
  try {
    const base64 = handle.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
    const raw = new TextDecoder().decode(bytes);
    const idx = raw.indexOf(":");
    if (idx < 0) return null;
    return { jti: raw.slice(0, idx), token: raw.slice(idx + 1) };
  } catch {
    return null;
  }
}
