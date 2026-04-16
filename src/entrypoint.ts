import { env, WorkerEntrypoint } from "cloudflare:workers";

import type { Env } from "./types";

import { hashPassword, verifyPassword } from "./utils/password";
import { signJWT } from "./utils/jwt";

import { Resend } from "resend";
import { generateRandomSecret } from "./utils/secret";

const resend = new Resend(env.RESEND_API_KEY);

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

    await this.env.DB.prepare(
      "INSERT INTO verifications (id, email, code, user) VALUES (?, ?, ?, ?)",
    )
      .bind(crypto.randomUUID(), email, verificationCode, userId)
      .run();

    if (!result) {
      return { success: false };
    }

    const verificationUrl = `${env.DOMAIN}/verify?code=${verificationCode}`;

    let emailSent = false;
    try {
      await resend.emails.send({
        from: "noreply@tenant365.cloud",
        to: email,
        template: {
          id: "email-verification",
          variables: {
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
}
