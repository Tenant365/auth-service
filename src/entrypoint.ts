import { env, WorkerEntrypoint } from "cloudflare:workers";

import type { Env } from "./types";

import { hashPassword, verifyPassword } from "./utils/password";
import { signJWT } from "./utils/jwt";

import { Resend } from "resend";
import { generateRandomSecret } from "./utils/secret";

const resend = new Resend(env.RESEND_API_KEY as string);

function encodeBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64Url(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));

  return new TextDecoder().decode(bytes);
}

type UserRecord = {
  id: string;
  display_name: string;
  email: string;
  password: string;
};

type JWTConfig = {
  issuer: string;
  audience: string;
};

export class AuthEntrypoint extends WorkerEntrypoint<Env> {
  async register(
    displayName: string,
    email: string,
    password: string,
    tenant?: string | null,
    domain?: string | null,
  ): Promise<{ success: boolean; userId?: string; emailSent?: boolean }> {
    const user = await this.env.DB.prepare(
      "SELECT * FROM users WHERE email = ?",
    )
      .bind(email)
      .first<UserRecord>();

    if (user) {
      throw new Error("User already exists");
    }

    const hashedPassword = await hashPassword(password);

    if (!hashedPassword) {
      throw new Error("Failed to hash password");
    }

    const result = await this.env.DB.prepare(
      "INSERT INTO users (id, display_name, email, password, tenant) VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
      .bind(crypto.randomUUID(), displayName, email, hashedPassword, tenant)
      .run();

    if (!result) {
      return { success: false };
    }

    const userId = result.results[0].id as string;

    const verificationCode = generateRandomSecret(32);
    const verificationCodeHash = await hashPassword(verificationCode);

    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    const verificationResult = await this.env.DB.prepare(
      "INSERT INTO verifications (id, email, code, user, expires_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
      .bind(crypto.randomUUID(), email, verificationCodeHash, userId, expiresAt)
      .run();

    if (!result) {
      return { success: false };
    }

    const verificationId = verificationResult.results[0].id as string;
    // base64url verificationId:verificationCode
    const verificationToken = encodeBase64Url(
      `${verificationId}:${verificationCode}`,
    );
    const verificationUrl = `${domain ?? "http://localhost:3000"}/verify?code=${verificationToken}`;

    let emailSent = false;
    try {
      await resend.emails.send({
        from: "noreply@tenant365.cloud",
        to: email,
        template: {
          id: "email-verification-default",
          variables: {
            T365_USER_NAME: displayName,
            T365_EMAIL_ADDRESS: email,
            EMAIL_VERIFICATION_URL: verificationUrl,
          },
        },
      });
      emailSent = true;
    } catch (error) {
      console.error(error);
      emailSent = false;
    }

    return { success: true, userId, emailSent };
  }

  async login(
    email: string,
    password: string,
    jwt: JWTConfig,
  ): Promise<{ success: boolean; token?: string }> {
    const user = await this.env.DB.prepare(
      "SELECT * FROM users WHERE email = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(email)
      .first<UserRecord>();

    if (!user) {
      throw new Error("User not found");
    }

    if (!(await verifyPassword(password, user.password))) {
      throw new Error("Invalid password");
    }

    const token = await signJWT(jwt.issuer, jwt.audience, this.env.JWT_SECRET, {
      sub: user.id,
      email: user.email,
      displayName: user.display_name,
    });

    return { success: true, token };
  }

  async verifyEmail(
    code: string,
  ): Promise<{ success: boolean; message?: string }> {
    const verificationToken = decodeBase64Url(code);
    const [verificationId, verificationCode] = verificationToken.split(":");

    const verification = await this.env.DB.prepare(
      "SELECT * FROM verifications WHERE id = ?",
    )
      .bind(verificationId)
      .first<VerificationRecord>();

    if (!verification) {
      return { success: false, message: "Verification not found" };
    }

    if (!(await verifyPassword(verificationCode, verification.code))) {
      return { success: false, message: "Invalid verification code" };
    }

    if (new Date(verification.expires_at) < new Date()) {
      return { success: false, message: "Verification expired" };
    }

    const result = await this.env.DB.prepare(
      "UPDATE users SET verified = 1 WHERE id = ?",
    )
      .bind(verification.user)
      .run();

    if (!result) {
      return { success: false, message: "Failed to verify user" };
    }

    return { success: true, message: "User verified successfully" };
  }
}

type VerificationRecord = {
  id: string;
  email: string;
  code: string;
  user: string;
  expires_at: string;
  created_at: string;
  updated_at: string;
};
