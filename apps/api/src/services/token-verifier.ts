import * as jose from 'jose';
import {
  ITokenVerifier,
  VerifiedTokenClaims,
  AuthenticationError,
} from '@modular-auth/core';

export interface SupabaseTokenVerifierOptions {
  readonly jwtSecret: string;
  readonly supabaseUrl?: string;
}

/**
 * Production-ready Supabase token verifier using cryptographic JWT verification.
 * Enforces signature validation, expiration checking, and audience verification.
 */
export class SupabaseTokenVerifier implements ITokenVerifier {
  private readonly secretKey: Uint8Array;
  private readonly supabaseUrl?: string;

  constructor(options: SupabaseTokenVerifierOptions) {
    if (!options.jwtSecret) {
      throw new Error('SupabaseTokenVerifier requires a non-empty jwtSecret');
    }
    this.secretKey = new TextEncoder().encode(options.jwtSecret);
    this.supabaseUrl = options.supabaseUrl;
  }

  public async verifyToken(token: string): Promise<VerifiedTokenClaims> {
    if (!token || typeof token !== 'string') {
      throw new AuthenticationError('Missing or empty authorization token');
    }

    try {
      const { payload } = await jose.jwtVerify(token, this.secretKey, {
        audience: 'authenticated',
        issuer: this.supabaseUrl ? `${this.supabaseUrl}/auth/v1` : undefined,
      });

      if (!payload.sub) {
        throw new AuthenticationError('Token payload missing required subject identifier');
      }

      const { aud: rawAud, ...restPayload } = payload;
      const audString = Array.isArray(rawAud) ? rawAud.join(',') : rawAud ?? '';

      return {
        ...restPayload,
        sub: payload.sub,
        email: typeof payload.email === 'string' ? payload.email : undefined,
        iss: payload.iss ?? '',
        aud: audString,
        iat: payload.iat ?? Math.floor(Date.now() / 1000),
        exp: payload.exp ?? Math.floor(Date.now() / 1000) + 3600,
      };
    } catch (err) {
      if (err instanceof AuthenticationError) {
        throw err;
      }

      const error = err as Error;
      if (error.name === 'JWTExpired') {
        throw new AuthenticationError('Access token has expired');
      }
      if (error.name === 'JWSSignatureVerificationFailed') {
        throw new AuthenticationError('Invalid token signature');
      }
      if (error.name === 'JWTClaimValidationFailed') {
        throw new AuthenticationError(`Token validation failed: ${error.message}`);
      }

      throw new AuthenticationError('Invalid or malformed access token');
    }
  }
}

/**
 * In-memory mock token verifier for hermetic unit and integration testing.
 * Allows simulating expired tokens, invalid signatures, and arbitrary user claims.
 */
export class MockTokenVerifier implements ITokenVerifier {
  private readonly validTokens = new Map<string, VerifiedTokenClaims>();

  public registerToken(token: string, claims: VerifiedTokenClaims): void {
    this.validTokens.set(token, claims);
  }

  public revokeToken(token: string): void {
    this.validTokens.delete(token);
  }

  public async verifyToken(token: string): Promise<VerifiedTokenClaims> {
    if (!token || typeof token !== 'string') {
      throw new AuthenticationError('Missing or empty authorization token');
    }

    if (token === 'expired-token') {
      throw new AuthenticationError('Access token has expired');
    }

    if (token === 'malformed-token' || token === 'invalid-signature-token') {
      throw new AuthenticationError('Invalid or malformed access token');
    }

    const claims = this.validTokens.get(token);
    if (!claims) {
      throw new AuthenticationError('Token not recognized or expired');
    }

    // Check expiration if exp is present
    const nowSeconds = Math.floor(Date.now() / 1000);
    if (claims.exp && claims.exp < nowSeconds) {
      throw new AuthenticationError('Access token has expired');
    }

    return claims;
  }
}
