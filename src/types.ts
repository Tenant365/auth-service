import type { D1Database, KVNamespace } from "@cloudflare/workers-types";

export type Env = {
  DB: D1Database;
  SESSIONS: KVNamespace;
  JWT_PRIVATE_KEY: string;
  JWT_PUBLIC_KEY: string;
  JWT_SECRET: string;
};

export type AuthContext = {
  userId: string;
  tenantId: string;
  email: string;
  roles: string[];
  scopes: string[];
  sessionId: string;
};
