import { env, WorkerEntrypoint } from "cloudflare:workers";

import type { Env } from "./types";

import { hashPassword, verifyPassword } from "./utils/password";
import { signJWT } from "./utils/jwt";
import { Resend } from "resend";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture as AuthenticatorTransport,
} from "@simplewebauthn/server";
import {
  verifyTOTP,
  buildTotpUri,
  generateBase32Secret,
  generateBackupCode,
  sha256Hex,
  verifySha256,
  generateRandomHex,
  encodeHandle,
  decodeHandle,
} from "./utils/totp";

const resend = new Resend(env.RESEND_API_KEY as string);

type JWTConfig = {
  issuer: string;
  audience: string;
};

type UserRecord = {
  id: string;
  display_name: string;
  email: string;
  password: string;
  tenant?: string | null;
  totp_secret?: string | null;
  totp_enabled?: boolean | number;
  two_factor_required?: boolean | number;
};

type LogContext = {
  ip?: string | null;
  country?: string | null;
  city?: string | null;
  userAgent?: string | null;
};

type PendingSession = {
  userId: string;
  email: string;
  displayName: string;
  context?: LogContext;
};

type FullSessionResult = {
  success: true;
  token: string;
  refreshToken: string;
  /** The auth-service session JTI — stored in sign_in_logs for revoke cleanup. */
  jti: string;
};

function encodeBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
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

export class AuthEntrypoint extends WorkerEntrypoint<Env> {
  // ─── Helpers ────────────────────────────────────────────────────────────────

  async #issueFullSession(
    user: { id: string; email: string; display_name: string },
    jwt: JWTConfig,
  ): Promise<FullSessionResult> {
    const jti = crypto.randomUUID();
    const token = await signJWT(jwt.issuer, jwt.audience, this.env.JWT_SECRET, {
      jti,
      sub: user.id,
      email: user.email,
      displayName: user.display_name,
    });

    await this.env.KV.put(
      `session:${jti}`,
      JSON.stringify({ userId: user.id, email: user.email, displayName: user.display_name }),
      { expirationTtl: 60 * 60 },
    );

    const refreshPlaintext = generateRandomHex(32);
    const refreshJti = crypto.randomUUID();
    const refreshHandle = encodeHandle(refreshJti, refreshPlaintext);
    const refreshHash = await sha256Hex(refreshPlaintext);

    await this.env.KV.put(
      `refresh:${refreshJti}`,
      JSON.stringify({ tokenHash: refreshHash, userId: user.id, email: user.email, displayName: user.display_name }),
      { expirationTtl: 60 * 60 * 24 * 14 },
    );

    return { success: true, token, refreshToken: refreshHandle, jti };
  }

  async #issuePendingSession(user: { id: string; email: string; display_name: string }, context?: LogContext): Promise<string> {
    const pendingToken = crypto.randomUUID();
    await this.env.KV.put(
      `pending_2fa:${pendingToken}`,
      JSON.stringify({ userId: user.id, email: user.email, displayName: user.display_name, context }),
      { expirationTtl: 60 * 5 },
    );
    return pendingToken;
  }

  async #writeSignInLog(userId: string, provider: string, context?: LogContext | null, authJti?: string | null): Promise<void> {
    try {
      await this.env.DB.prepare(
        "INSERT INTO sign_in_logs (id, user_id, created_at, ip_address, country, city, user_agent, provider, auth_jti) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
        .bind(
          crypto.randomUUID(),
          userId,
          Math.floor(Date.now() / 1000),
          context?.ip ?? null,
          context?.country ?? null,
          context?.city ?? null,
          context?.userAgent ?? null,
          provider,
          authJti ?? null,
        )
        .run();
    } catch { /* best-effort */ }
  }

  async #verifyBackupCodeForUser(userId: string, code: string): Promise<boolean> {
    const normalized = code.replace(/\s|-/g, "").toUpperCase();
    const codes = await this.env.DB.prepare(
      "SELECT id, code_hash FROM totp_backup_codes WHERE user_id = ? AND used_at IS NULL",
    )
      .bind(userId)
      .all<{ id: string; code_hash: string }>();

    for (const row of codes.results) {
      if (await verifySha256(normalized, row.code_hash)) {
        await this.env.DB.prepare("UPDATE totp_backup_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?")
          .bind(row.id)
          .run();
        return true;
      }
    }
    return false;
  }

  // ─── Registration ───────────────────────────────────────────────────────────

  async register(
    displayName: string,
    email: string,
    password: string,
    tenant?: string | null,
    domain?: string | null,
  ): Promise<{ success: boolean; userId?: string; emailSent?: boolean }> {
    const existing = await this.env.DB.prepare("SELECT id FROM users WHERE email = ?")
      .bind(email)
      .first<{ id: string }>();

    if (existing) throw new Error("User already exists");

    const hashedPassword = await hashPassword(password);
    if (!hashedPassword) throw new Error("Failed to hash password");

    const result = await this.env.DB.prepare(
      "INSERT INTO users (id, display_name, email, password, tenant) VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
      .bind(crypto.randomUUID(), displayName, email, hashedPassword, tenant)
      .run();

    if (!result) return { success: false };

    const userId = result.results[0].id as string;

    const verificationCode = generateRandomHex(16);
    const verificationCodeHash = await hashPassword(verificationCode);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    const verificationResult = await this.env.DB.prepare(
      "INSERT INTO verifications (id, email, code, user, expires_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
      .bind(crypto.randomUUID(), email, verificationCodeHash, userId, expiresAt)
      .run();

    const verificationId = verificationResult.results[0].id as string;
    const verificationToken = encodeBase64Url(`${verificationId}:${verificationCode}`);
    const verificationUrl = `${domain ?? "http://localhost:3000"}/verify?code=${verificationToken}`;

    resend.emails.send({
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

    return { success: true, userId, emailSent: true };
  }

  // ─── Login ──────────────────────────────────────────────────────────────────

  async login(
    email: string,
    password: string,
    jwt: JWTConfig,
    context?: LogContext,
  ): Promise<{
    success: boolean;
    token?: string;
    refreshToken?: string;
    requiresTwoFactor?: boolean;
    requiresTwoFactorSetup?: boolean;
    pendingToken?: string;
  }> {
    const user = await this.env.DB.prepare(
      `SELECT u.id, u.display_name, u.email, u.password, u.tenant,
              u.totp_secret, u.totp_enabled, t.two_factor_required
       FROM users u
       LEFT JOIN tenants t ON u.tenant = t.id
       WHERE u.email = ? AND u.enabled = 1 AND u.deleted_at IS NULL`,
    )
      .bind(email)
      .first<UserRecord>();

    if (!user) throw new Error("User not found");
    if (!(await verifyPassword(password, user.password))) throw new Error("Invalid password");

    const twoFactorRequired = Boolean(user.two_factor_required);
    const totpEnabled = Boolean(user.totp_enabled);

    if (twoFactorRequired && !totpEnabled) {
      const pendingToken = await this.#issuePendingSession(user, context);
      return { success: true, requiresTwoFactorSetup: true, pendingToken };
    }

    if (totpEnabled) {
      const pendingToken = await this.#issuePendingSession(user, context);
      return { success: true, requiresTwoFactor: true, pendingToken };
    }

    const session = await this.#issueFullSession(user, jwt);
    void this.#writeSignInLog(user.id, "password", context, session.jti);
    return session;
  }

  // ─── 2FA: Setup (forced flow – pending token) ────────────────────────────────

  async setupTotp(pendingToken: string): Promise<{
    success: boolean;
    secret?: string;
    uri?: string;
    message?: string;
  }> {
    const pending = await this.env.KV.get<PendingSession>(`pending_2fa:${pendingToken}`, "json");
    if (!pending) return { success: false, message: "Session expired or invalid" };

    const secret = generateBase32Secret(20);
    await this.env.KV.put(`totp_setup:${pending.userId}`, JSON.stringify({ secret }), {
      expirationTtl: 60 * 10,
    });

    const issuer = "Tenant365";
    const uri = buildTotpUri(secret, pending.email, issuer);
    return { success: true, secret, uri };
  }

  async completeTotpSetup(
    pendingToken: string,
    code: string,
    jwt: JWTConfig,
  ): Promise<{
    success: boolean;
    backupCodes?: string[];
    token?: string;
    refreshToken?: string;
    message?: string;
  }> {
    const pending = await this.env.KV.get<PendingSession>(`pending_2fa:${pendingToken}`, "json");
    if (!pending) return { success: false, message: "Session expired or invalid" };

    const setup = await this.env.KV.get<{ secret: string }>(`totp_setup:${pending.userId}`, "json");
    if (!setup) return { success: false, message: "TOTP setup not initiated or expired" };

    if (!(await verifyTOTP(setup.secret, code))) {
      return { success: false, message: "Invalid authenticator code" };
    }

    await this.env.DB.prepare(
      "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
    )
      .bind(setup.secret, pending.userId)
      .run();

    await this.env.KV.delete(`totp_setup:${pending.userId}`);
    await this.env.KV.delete(`pending_2fa:${pendingToken}`);

    const backupCodes = await this.#storeNewBackupCodes(pending.userId);
    const session = await this.#issueFullSession(
      { id: pending.userId, email: pending.email, display_name: pending.displayName },
      jwt,
    );

    return { ...session, backupCodes };
  }

  // ─── 2FA: Setup (voluntary – logged-in user) ─────────────────────────────────

  async setupTotpForUser(userId: string): Promise<{
    success: boolean;
    secret?: string;
    uri?: string;
    message?: string;
  }> {
    const user = await this.env.DB.prepare("SELECT id, email FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL")
      .bind(userId)
      .first<{ id: string; email: string }>();
    if (!user) return { success: false, message: "User not found" };

    const secret = generateBase32Secret(20);
    await this.env.KV.put(`totp_setup:${userId}`, JSON.stringify({ secret }), {
      expirationTtl: 60 * 10,
    });

    const uri = buildTotpUri(secret, user.email, "Tenant365");
    return { success: true, secret, uri };
  }

  async enableTotp(
    userId: string,
    code: string,
  ): Promise<{ success: boolean; backupCodes?: string[]; message?: string }> {
    const setup = await this.env.KV.get<{ secret: string }>(`totp_setup:${userId}`, "json");
    if (!setup) return { success: false, message: "TOTP setup not initiated or expired" };

    if (!(await verifyTOTP(setup.secret, code))) {
      return { success: false, message: "Invalid authenticator code" };
    }

    await this.env.DB.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?")
      .bind(setup.secret, userId)
      .run();

    await this.env.KV.delete(`totp_setup:${userId}`);
    const backupCodes = await this.#storeNewBackupCodes(userId);
    return { success: true, backupCodes };
  }

  // ─── 2FA: Verify (login flow) ─────────────────────────────────────────────

  async verifyTotp(
    pendingToken: string,
    code: string,
    jwt: JWTConfig,
  ): Promise<{ success: boolean; token?: string; refreshToken?: string; message?: string }> {
    const pending = await this.env.KV.get<PendingSession>(`pending_2fa:${pendingToken}`, "json");
    if (!pending) return { success: false, message: "Session expired or invalid" };

    const user = await this.env.DB.prepare(
      "SELECT id, display_name, email, totp_secret FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(pending.userId)
      .first<{ id: string; display_name: string; email: string; totp_secret: string | null }>();

    if (!user?.totp_secret) return { success: false, message: "User not found or 2FA not configured" };

    if (!(await verifyTOTP(user.totp_secret, code))) {
      return { success: false, message: "Invalid authenticator code" };
    }

    await this.env.KV.delete(`pending_2fa:${pendingToken}`);
    const session = await this.#issueFullSession(user, jwt);
    void this.#writeSignInLog(user.id, "password", pending.context, session.jti);
    return session;
  }

  async verifyBackupCode(
    pendingToken: string,
    code: string,
    jwt: JWTConfig,
  ): Promise<{ success: boolean; token?: string; refreshToken?: string; message?: string }> {
    const pending = await this.env.KV.get<PendingSession>(`pending_2fa:${pendingToken}`, "json");
    if (!pending) return { success: false, message: "Session expired or invalid" };

    const user = await this.env.DB.prepare(
      "SELECT id, display_name, email FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(pending.userId)
      .first<{ id: string; display_name: string; email: string }>();

    if (!user) return { success: false, message: "User not found" };

    if (!(await this.#verifyBackupCodeForUser(pending.userId, code))) {
      return { success: false, message: "Invalid backup code" };
    }

    await this.env.KV.delete(`pending_2fa:${pendingToken}`);
    const session = await this.#issueFullSession(user, jwt);
    void this.#writeSignInLog(user.id, "password", pending.context, session.jti);
    return session;
  }

  // ─── 2FA: Manage (settings) ───────────────────────────────────────────────

  async disableTotp(
    userId: string,
    code: string,
  ): Promise<{ success: boolean; message?: string }> {
    const user = await this.env.DB.prepare(
      "SELECT totp_secret FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(userId)
      .first<{ totp_secret: string | null }>();

    if (!user?.totp_secret) return { success: false, message: "2FA is not enabled" };

    const totpValid = await verifyTOTP(user.totp_secret, code);
    const backupValid = totpValid ? false : await this.#verifyBackupCodeForUser(userId, code);

    if (!totpValid && !backupValid) return { success: false, message: "Invalid code" };

    await this.env.DB.prepare("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?")
      .bind(userId)
      .run();
    await this.env.DB.prepare("DELETE FROM totp_backup_codes WHERE user_id = ?").bind(userId).run();

    return { success: true };
  }

  async regenerateBackupCodes(
    userId: string,
    code: string,
  ): Promise<{ success: boolean; backupCodes?: string[]; message?: string }> {
    const user = await this.env.DB.prepare(
      "SELECT totp_secret FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(userId)
      .first<{ totp_secret: string | null }>();

    if (!user?.totp_secret) return { success: false, message: "2FA is not enabled" };
    if (!(await verifyTOTP(user.totp_secret, code))) return { success: false, message: "Invalid authenticator code" };

    await this.env.DB.prepare("DELETE FROM totp_backup_codes WHERE user_id = ?").bind(userId).run();
    const backupCodes = await this.#storeNewBackupCodes(userId);
    return { success: true, backupCodes };
  }

  async getTotpStatus(userId: string): Promise<{ enabled: boolean; backupCodesRemaining: number }> {
    const user = await this.env.DB.prepare(
      "SELECT totp_enabled FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(userId)
      .first<{ totp_enabled: boolean | number }>();

    const enabled = Boolean(user?.totp_enabled);

    let backupCodesRemaining = 0;
    if (enabled) {
      const count = await this.env.DB.prepare(
        "SELECT COUNT(*) as cnt FROM totp_backup_codes WHERE user_id = ? AND used_at IS NULL",
      )
        .bind(userId)
        .first<{ cnt: number }>();
      backupCodesRemaining = count?.cnt ?? 0;
    }

    return { enabled, backupCodesRemaining };
  }

  async #storeNewBackupCodes(userId: string): Promise<string[]> {
    const codes = Array.from({ length: 10 }, generateBackupCode);
    const stmt = this.env.DB.prepare(
      "INSERT INTO totp_backup_codes (id, user_id, code_hash) VALUES (?, ?, ?)",
    );

    for (const code of codes) {
      const normalized = code.replace(/-/g, "");
      const hash = await sha256Hex(normalized);
      await stmt.bind(crypto.randomUUID(), userId, hash).run();
    }

    return codes;
  }

  // ─── Refresh Token ────────────────────────────────────────────────────────

  async refresh(
    refreshTokenHandle: string,
    jwt: JWTConfig,
  ): Promise<{ success: boolean; token?: string; refreshToken?: string; message?: string }> {
    const parsed = decodeHandle(refreshTokenHandle);
    if (!parsed) return { success: false, message: "Invalid refresh token" };

    const { jti, token } = parsed;
    const stored = await this.env.KV.get<{
      tokenHash: string;
      userId: string;
      email: string;
      displayName: string;
    }>(`refresh:${jti}`, "json");

    if (!stored) return { success: false, message: "Refresh token expired or revoked" };

    if (!(await verifySha256(token, stored.tokenHash))) {
      return { success: false, message: "Invalid refresh token" };
    }

    await this.env.KV.delete(`refresh:${jti}`);

    const user = await this.env.DB.prepare(
      "SELECT id, display_name, email FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(stored.userId)
      .first<{ id: string; display_name: string; email: string }>();

    if (!user) return { success: false, message: "User not found or deactivated" };

    const session = await this.#issueFullSession(user, jwt);
    return session;
  }

  async logout(sessionJti: string, refreshTokenHandle?: string): Promise<void> {
    await this.env.KV.delete(`session:${sessionJti}`);

    if (refreshTokenHandle) {
      const parsed = decodeHandle(refreshTokenHandle);
      if (parsed) {
        await this.env.KV.delete(`refresh:${parsed.jti}`);
      }
    }
  }

  async checkSession(jti: string): Promise<boolean> {
    const session = await this.env.KV.get(`session:${jti}`);
    return session !== null;
  }

  // ─── Password Management ─────────────────────────────────────────────────

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<{ success: boolean; message?: string }> {
    const user = await this.env.DB.prepare(
      "SELECT id, password FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(userId)
      .first<{ id: string; password: string }>();

    if (!user) return { success: false, message: "User not found" };
    if (!(await verifyPassword(currentPassword, user.password))) {
      return { success: false, message: "Current password is incorrect" };
    }

    const newHash = await hashPassword(newPassword);
    if (!newHash) return { success: false, message: "Failed to hash password" };

    await this.env.DB.prepare("UPDATE users SET password = ? WHERE id = ?")
      .bind(newHash, userId)
      .run();

    return { success: true };
  }

  async getUserProfile(userId: string): Promise<{ id: string; email: string; display_name: string } | null> {
    return this.env.DB.prepare(
      "SELECT id, email, display_name FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(userId)
      .first<{ id: string; email: string; display_name: string }>();
  }

  // ─── Email Verification ───────────────────────────────────────────────────

  async verifyEmail(code: string): Promise<{ success: boolean; message?: string }> {
    const decoded = decodeBase64Url(code);
    const [verificationId, verificationCode] = decoded.split(":");

    const verification = await this.env.DB.prepare("SELECT * FROM verifications WHERE id = ?")
      .bind(verificationId)
      .first<VerificationRecord>();

    if (!verification) return { success: false, message: "Verification not found" };
    if (!(await verifyPassword(verificationCode, verification.code))) {
      return { success: false, message: "Invalid verification code" };
    }
    if (new Date(verification.expires_at) < new Date()) {
      return { success: false, message: "Verification expired" };
    }

    await this.env.DB.prepare("UPDATE users SET verified = 1 WHERE id = ?")
      .bind(verification.user)
      .run();

    return { success: true, message: "User verified successfully" };
  }

  // ─── SSO Login ────────────────────────────────────────────────────────────

  async loginWithSSO(
    email: string,
    provider: string,
    externalUserId: string,
    accessToken: string,
    expiresIn: number,
    jwt: JWTConfig,
    context?: LogContext,
  ): Promise<{ success: boolean; token?: string; refreshToken?: string }> {
    // 1. Try to find the user via the persistent SSO links table first.
    let user: { id: string; display_name: string; email: string } | null = null;

    const link = await this.env.DB.prepare(
      `SELECT u.id, u.display_name, u.email
       FROM user_sso_links l
       JOIN users u ON u.id = l.user_id
       WHERE l.provider = ? AND l.external_user_id = ?
         AND u.enabled = 1 AND u.deleted_at IS NULL`,
    )
      .bind(provider, externalUserId)
      .first<{ id: string; display_name: string; email: string }>();

    if (link) {
      user = link;
      // Keep external_email up-to-date in case the provider email changed.
      await this.env.DB.prepare(
        "UPDATE user_sso_links SET external_email = ? WHERE user_id = ? AND provider = ?",
      ).bind(email, user.id, provider).run().catch(() => {});
    }

    // 2. Fall back to email lookup + auto-link on first SSO login.
    if (!user) {
      user = await this.env.DB.prepare(
        "SELECT id, display_name, email FROM users WHERE email = ? AND enabled = 1 AND deleted_at IS NULL",
      )
        .bind(email)
        .first<{ id: string; display_name: string; email: string }>();

      if (!user) throw new Error("User not found");

      // Auto-link: persist so future logins skip the email lookup.
      await this.env.DB.prepare(
        `INSERT INTO user_sso_links (user_id, provider, external_user_id, external_email, linked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (user_id, provider) DO UPDATE SET
           external_user_id = excluded.external_user_id,
           external_email    = excluded.external_email`,
      ).bind(user.id, provider, externalUserId, email, Math.floor(Date.now() / 1000)).run().catch(() => {});
    }

    const session = await this.#issueFullSession(user, jwt);
    void this.#writeSignInLog(user.id, provider, context, session.jti);
    return session;
  }

  // ─── SSO Link Management ─────────────────────────────────────────────────────

  /** Issue a short-lived opaque token that the account portal hands to the login
   *  portal so the SSO callback can verify which user to link without trusting
   *  query-string user IDs. */
  async issueLinkToken(userId: string): Promise<string> {
    const token = crypto.randomUUID();
    await this.env.KV.put(
      `sso_link_token:${token}`,
      JSON.stringify({ userId }),
      { expirationTtl: 60 * 10 },
    );
    return token;
  }

  /** Called by the login portal SSO callback in link mode.
   *  Validates the token, then upserts the SSO link for the resolved user. */
  async consumeLinkToken(
    token: string,
    provider: string,
    externalUserId: string,
    externalEmail: string | null,
  ): Promise<{ success: boolean; message?: string }> {
    const stored = await this.env.KV.get<{ userId: string }>(`sso_link_token:${token}`, "json");
    if (!stored) return { success: false, message: "Link token expired or invalid" };

    await this.env.KV.delete(`sso_link_token:${token}`);

    try {
      // Ensure no other account already owns this provider identity.
      const conflict = await this.env.DB.prepare(
        "SELECT user_id FROM user_sso_links WHERE provider = ? AND external_user_id = ? AND user_id != ?",
      ).bind(provider, externalUserId, stored.userId).first<{ user_id: string }>();

      if (conflict) {
        return { success: false, message: "This provider account is already linked to a different user" };
      }

      await this.env.DB.prepare(
        `INSERT INTO user_sso_links (user_id, provider, external_user_id, external_email, linked_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (user_id, provider) DO UPDATE SET
           external_user_id = excluded.external_user_id,
           external_email   = excluded.external_email,
           linked_at        = excluded.linked_at`,
      ).bind(stored.userId, provider, externalUserId, externalEmail, Math.floor(Date.now() / 1000)).run();

      return { success: true };
    } catch (e) {
      return { success: false, message: e instanceof Error ? e.message : "Failed to link account" };
    }
  }

  async listSSOLinks(userId: string): Promise<Array<{
    provider: string;
    external_email: string | null;
    linked_at: number;
  }>> {
    const result = await this.env.DB.prepare(
      "SELECT provider, external_email, linked_at FROM user_sso_links WHERE user_id = ? ORDER BY linked_at ASC",
    )
      .bind(userId)
      .all<{ provider: string; external_email: string | null; linked_at: number }>();
    return result.results;
  }

  async unlinkSSO(
    userId: string,
    provider: string,
  ): Promise<{ success: boolean; message?: string }> {
    try {
      const existing = await this.env.DB.prepare(
        "SELECT user_id FROM user_sso_links WHERE user_id = ? AND provider = ?",
      ).bind(userId, provider).first<{ user_id: string }>();

      if (!existing) return { success: false, message: "Provider not linked" };

      await this.env.DB.prepare(
        "DELETE FROM user_sso_links WHERE user_id = ? AND provider = ?",
      ).bind(userId, provider).run();

      return { success: true };
    } catch (e) {
      return { success: false, message: e instanceof Error ? e.message : "Failed to unlink account" };
    }
  }

  async getSignInLogs(userId: string, limit = 20): Promise<Array<{
    id: string;
    user_id: string;
    created_at: number;
    ip_address: string | null;
    country: string | null;
    city: string | null;
    user_agent: string | null;
    provider: string;
    oauth2_jti: string | null;
    revoked_at: number | null;
  }>> {
    const result = await this.env.DB.prepare(
      "SELECT id, user_id, created_at, ip_address, country, city, user_agent, provider, oauth2_jti, revoked_at FROM sign_in_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
    )
      .bind(userId, limit)
      .all<{
        id: string;
        user_id: string;
        created_at: number;
        ip_address: string | null;
        country: string | null;
        city: string | null;
        user_agent: string | null;
        provider: string;
        oauth2_jti: string | null;
        revoked_at: number | null;
      }>();
    return result.results;
  }

  // ─── Sign-in log: link OAuth2 JTI ────────────────────────────────────────

  async linkSignInLogOAuth2Jti(userId: string, oauth2Jti: string): Promise<void> {
    try {
      await this.env.DB.prepare(
        "UPDATE sign_in_logs SET oauth2_jti = ? WHERE user_id = ? AND oauth2_jti IS NULL ORDER BY created_at DESC LIMIT 1",
      )
        .bind(oauth2Jti, userId)
        .run();
    } catch { /* best-effort */ }
  }

  // ─── Session revocation ──────────────────────────────────────────────────────

  /**
   * Revoke the auth-service session associated with a sign-in log entry and
   * mark the log as revoked. Called from the account portal after the OAuth2
   * session has already been invalidated.
   */
  async revokeSessionByLogId(
    userId: string,
    logId: string,
  ): Promise<{ success: boolean; message?: string }> {
    try {
      const log = await this.env.DB.prepare(
        "SELECT auth_jti FROM sign_in_logs WHERE id = ? AND user_id = ?",
      )
        .bind(logId, userId)
        .first<{ auth_jti: string | null }>();

      if (!log) return { success: false, message: "Sign-in log not found" };

      // Delete auth-service session from KV (best-effort — may already be expired)
      if (log.auth_jti) {
        await this.env.KV.delete(`session:${log.auth_jti}`).catch(() => {});
      }

      // Mark the log as revoked in the DB
      await this.env.DB.prepare(
        "UPDATE sign_in_logs SET revoked_at = ? WHERE id = ? AND user_id = ?",
      )
        .bind(Math.floor(Date.now() / 1000), logId, userId)
        .run();

      return { success: true };
    } catch (e) {
      return { success: false, message: e instanceof Error ? e.message : "Revocation failed" };
    }
  }

  // ─── Passkeys ────────────────────────────────────────────────────────────

  async generatePasskeyRegistrationOptions(userId: string): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const user = await this.env.DB.prepare(
      "SELECT id, email, display_name FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
    )
      .bind(userId)
      .first<{ id: string; email: string; display_name: string }>();

    if (!user) throw new Error("User not found");

    // Fetch existing credentials to exclude
    const existing = await this.env.DB.prepare(
      "SELECT id FROM passkey_credentials WHERE user_id = ?",
    )
      .bind(userId)
      .all<{ id: string }>();

    const options = await generateRegistrationOptions({
      rpName: "Tenant365",
      rpID: "tenant365.cloud",
      userName: user.email,
      userDisplayName: user.display_name,
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        requireResidentKey: true,
        residentKey: "required",
        userVerification: "required",
      },
      excludeCredentials: existing.results.map((c) => ({ id: c.id })),
      timeout: 60000,
    });

    // Store challenge in KV keyed by userId (one pending registration at a time)
    await this.env.KV.put(
      `passkey:reg-challenge:${userId}`,
      options.challenge,
      { expirationTtl: 60 * 5 },
    );

    return options;
  }

  async verifyPasskeyRegistration(
    userId: string,
    response: RegistrationResponseJSON,
    name: string,
  ): Promise<{ success: boolean; credentialId?: string; message?: string }> {
    const expectedChallenge = await this.env.KV.get(`passkey:reg-challenge:${userId}`);
    if (!expectedChallenge) return { success: false, message: "Challenge expired or not found" };

    try {
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge,
        expectedOrigin: ["https://account.tenant365.cloud", "http://localhost:3000"],
        expectedRPID: "tenant365.cloud",
        requireUserVerification: true,
      });

      if (!verification.verified || !verification.registrationInfo) {
        return { success: false, message: "Passkey registration verification failed" };
      }

      await this.env.KV.delete(`passkey:reg-challenge:${userId}`);

      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

      await this.env.DB.prepare(
        "INSERT INTO passkey_credentials (id, user_id, name, public_key, counter, device_type, backed_up, transports, aaguid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
        .bind(
          credential.id,
          userId,
          name,
          isoBase64URL.fromBuffer(credential.publicKey),
          credential.counter,
          credentialDeviceType,
          credentialBackedUp ? 1 : 0,
          credential.transports ? JSON.stringify(credential.transports) : null,
          verification.registrationInfo.aaguid ?? null,
          Math.floor(Date.now() / 1000),
        )
        .run();

      return { success: true, credentialId: credential.id };
    } catch (e) {
      return { success: false, message: e instanceof Error ? e.message : "Verification failed" };
    }
  }

  async generatePasskeyAuthenticationOptions(): Promise<{
    options: PublicKeyCredentialRequestOptionsJSON;
    challengeId: string;
  }> {
    const options = await generateAuthenticationOptions({
      rpID: "tenant365.cloud",
      allowCredentials: [],
      userVerification: "required",
      timeout: 60000,
    });

    const challengeId = crypto.randomUUID();
    await this.env.KV.put(
      `passkey:auth-challenge:${challengeId}`,
      options.challenge,
      { expirationTtl: 60 * 5 },
    );

    return { options, challengeId };
  }

  async verifyPasskeyAuthentication(
    challengeId: string,
    response: AuthenticationResponseJSON,
    jwt: JWTConfig,
    context?: LogContext | null,
  ): Promise<{ success: boolean; token?: string; refreshToken?: string; message?: string }> {
    const expectedChallenge = await this.env.KV.get(`passkey:auth-challenge:${challengeId}`);
    if (!expectedChallenge) return { success: false, message: "Challenge expired or not found" };

    const credential = await this.env.DB.prepare(
      "SELECT id, user_id, public_key, counter, transports FROM passkey_credentials WHERE id = ?",
    )
      .bind(response.id)
      .first<{ id: string; user_id: string; public_key: string; counter: number; transports: string | null }>();

    if (!credential) return { success: false, message: "Passkey not found" };

    try {
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge,
        expectedOrigin: ["https://login.tenant365.cloud", "http://localhost:3000"],
        expectedRPID: "tenant365.cloud",
        credential: {
          id: credential.id,
          publicKey: isoBase64URL.toBuffer(credential.public_key),
          counter: credential.counter,
          transports: credential.transports
            ? (JSON.parse(credential.transports) as AuthenticatorTransport[])
            : undefined,
        },
        requireUserVerification: true,
      });

      if (!verification.verified) return { success: false, message: "Passkey authentication failed" };

      await this.env.KV.delete(`passkey:auth-challenge:${challengeId}`);

      // Update counter and last_used_at
      await this.env.DB.prepare(
        "UPDATE passkey_credentials SET counter = ?, last_used_at = ? WHERE id = ?",
      )
        .bind(verification.authenticationInfo.newCounter, Math.floor(Date.now() / 1000), credential.id)
        .run();

      const user = await this.env.DB.prepare(
        "SELECT id, display_name, email FROM users WHERE id = ? AND enabled = 1 AND deleted_at IS NULL",
      )
        .bind(credential.user_id)
        .first<{ id: string; display_name: string; email: string }>();

      if (!user) return { success: false, message: "User not found or deactivated" };

      const session = await this.#issueFullSession(user, jwt);
      void this.#writeSignInLog(user.id, "passkey", context, session.jti);
      return session;
    } catch (e) {
      return { success: false, message: e instanceof Error ? e.message : "Verification failed" };
    }
  }

  async listPasskeys(userId: string): Promise<Array<{
    id: string;
    name: string;
    device_type: string;
    backed_up: boolean;
    created_at: number;
    last_used_at: number | null;
    aaguid: string | null;
  }>> {
    const result = await this.env.DB.prepare(
      "SELECT id, name, device_type, backed_up, created_at, last_used_at, aaguid FROM passkey_credentials WHERE user_id = ? ORDER BY created_at DESC",
    )
      .bind(userId)
      .all<{
        id: string;
        name: string;
        device_type: string;
        backed_up: number;
        created_at: number;
        last_used_at: number | null;
        aaguid: string | null;
      }>();

    return result.results.map((r) => ({
      ...r,
      backed_up: Boolean(r.backed_up),
    }));
  }

  async deletePasskey(userId: string, credentialId: string): Promise<{ success: boolean; message?: string }> {
    try {
      const existing = await this.env.DB.prepare(
        "SELECT id FROM passkey_credentials WHERE id = ? AND user_id = ?",
      )
        .bind(credentialId, userId)
        .first<{ id: string }>();

      if (!existing) return { success: false, message: "Passkey not found" };

      await this.env.DB.prepare("DELETE FROM passkey_credentials WHERE id = ? AND user_id = ?")
        .bind(credentialId, userId)
        .run();

      return { success: true };
    } catch (e) {
      return { success: false, message: e instanceof Error ? e.message : "Failed to delete passkey" };
    }
  }
}
