import { SignJWT } from "jose";

export const signJWT = async (
  issuer: string,
  audience: string,
  payload: any,
) => {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(payload.sub)
    .setIssuer(issuer)
    .setAudience(audience)
    .setExpirationTime("1h")
    .setIssuedAt()
    .sign(new TextEncoder().encode(process.env.JWT_SECRET));
};
