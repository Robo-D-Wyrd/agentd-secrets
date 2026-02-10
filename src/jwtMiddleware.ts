import { Request, Response, NextFunction } from 'express';
import * as jose from 'jose';
import logger from './logger';

let jwks: jose.JWTVerifyGetKey | null = null;
let jwksIssuer: string = '';
let jwksAudience: string = '';

export function initJwtMiddleware(issuerURL: string, audience: string): void {
  const jwksUri = new URL('.well-known/openid-configuration', issuerURL.endsWith('/') ? issuerURL : issuerURL + '/');
  jwks = jose.createRemoteJWKSet(new URL(`${issuerURL.replace(/\/$/, '')}/protocol/openid-connect/certs`));
  jwksIssuer = issuerURL;
  jwksAudience = audience;
}

export async function jwtMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!jwks) {
    res.status(500).json({ error: 'JWT middleware not initialized' });
    return;
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.slice(7);

  try {
    const verifyOptions: jose.JWTVerifyOptions = {
      issuer: jwksIssuer,
    };
    if (jwksAudience) {
      verifyOptions.audience = jwksAudience;
    }

    const { payload } = await jose.jwtVerify(token, jwks, verifyOptions);
    (req as Request & { jwtPayload?: jose.JWTPayload }).jwtPayload = payload;
    next();
  } catch (err) {
    logger.warn('JWT verification failed', { error: (err as Error).message });
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
