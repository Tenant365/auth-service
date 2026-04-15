import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./types";
import { hashPassword, verifyPassword } from "./utils/password";
import { signJWT } from "./utils/jwt";

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
  ): Promise<void> {
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

    await this.env.DB.prepare(
      "INSERT INTO users (id, display_name, email, password, tenant) VALUES (?, ?, ?, ?, ?)",
    )
      .bind(crypto.randomUUID(), displayName, email, hashedPassword, tenant)
      .run();
  }

  async login(
    email: string,
    password: string,
    jwt: JWTConfig,
  ): Promise<string> {
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

    return signJWT(jwt.issuer, jwt.audience, this.env.JWT_SECRET, {
      sub: user.id,
      email: user.email,
      displayName: user.display_name,
    });
  }
}
