import { SignJWT } from "jose";

import type { Env } from "../types";

export const signJWT = async (
  issuer: string,
  audience: string,
  secret: string,
  payload: any,
) => {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(payload.sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(new TextEncoder().encode(secret));
};
