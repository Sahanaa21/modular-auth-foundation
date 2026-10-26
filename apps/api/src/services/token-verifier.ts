import * as jose from 'jose';
import { SupabaseClient } from '@supabase/supabase-js';
import {
  ITokenVerifier,
  VerifiedTokenClaims,
  AuthenticationError,
} from '@modular-auth/core';

export interface SupabaseTokenVerifierOptions {
  /**
   * Supabase JWT secret for symmetric HS256 verification (legacy or development).
   */
  readonly jwtSecret?: string;

  /**
   * Supabase project base URL (e.g. 'https://<project-ref>.supabase.co').
   * Used to resolve the remote JWKS endpoint and validate token issuer.
   */
  readonly supabaseUrl?: string;

  /**
   * Expected audience (defaults to 'authenticated').
   */
  readonly audience?: string | string[];

  /**
   * Expected issuer(s). Defaults to ['${supabaseUrl}/auth/v1', '${supabaseUrl}/auth/v1/', 'supabase'].
   */
  readonly issuer?: string | string[];

  /**
   * Custom JWKS resolver or JSONWebKeySet for offline/hermetic testing.
   */
  readonly jwks?: jose.JWTVerifyGetKey | jose.JSONWebKeySet;

  /**
   * Optional Supabase client instance for fallback verification via Supabase Auth API.
   */
  readonly supabaseClient?: SupabaseClient;

  /**
   * Explicitly allowed algorithms (defaults to ['ES256', 'RS256', 'HS256']).
   * Never permits 'none'.
   */
  readonly allowedAlgorithms?: readonly string[];
}

/**
 * Production-ready Supabase token verifier supporting both modern ES256/RS256 (JWKS)
 * and legacy HS256 (symmetric HMAC) token signing configurations.
 * Enforces cryptographic signature verification, expiration checking, audience verification,
 * and issuer validation against the configured Supabase project.
 */
export class SupabaseTokenVerifier implements ITokenVerifier {
  private readonly secretKey?: Uint8Array;
  private readonly normalizedUrl?: string;
  private readonly jwksResolver?: jose.JWTVerifyGetKey;
  private readonly supabaseClient?: SupabaseClient;
  private readonly allowedAlgorithms: readonly string[];
  private readonly audience: string | string[];
  private readonly validIssuers?: string[];

  constructor(options: SupabaseTokenVerifierOptions = {}) {
    if (!options.jwtSecret && !options.supabaseUrl && !options.jwks && !options.supabaseClient) {
      throw new Error(
        'SupabaseTokenVerifier requires at least one of: jwtSecret, supabaseUrl, jwks, or supabaseClient'
      );
    }

    if (options.jwtSecret) {
      this.secretKey = new TextEncoder().encode(options.jwtSecret);
    }

    if (options.supabaseUrl) {
      this.normalizedUrl = options.supabaseUrl.replace(/\/+$/, '');
    }

    if (options.jwks) {
      if (typeof options.jwks === 'function') {
        this.jwksResolver = options.jwks;
      } else if (typeof options.jwks === 'object' && 'keys' in options.jwks) {
        this.jwksResolver = jose.createLocalJWKSet(options.jwks);
      }
    } else if (this.normalizedUrl) {
      const jwksUrl = new URL(`${this.normalizedUrl}/auth/v1/.well-known/jwks.json`);
      this.jwksResolver = jose.createRemoteJWKSet(jwksUrl);
    }

    this.supabaseClient = options.supabaseClient;
    this.allowedAlgorithms = options.allowedAlgorithms ?? ['ES256', 'RS256', 'HS256'];
    this.audience = options.audience ?? 'authenticated';

    if (options.issuer) {
      this.validIssuers = Array.isArray(options.issuer) ? options.issuer : [options.issuer];
    } else if (this.normalizedUrl) {
      this.validIssuers = [
        `${this.normalizedUrl}/auth/v1`,
        `${this.normalizedUrl}/auth/v1/`,
        'supabase',
      ];
    }
  }

  public async verifyToken(token: string): Promise<VerifiedTokenClaims> {
    if (!token || typeof token !== 'string') {
      throw new AuthenticationError('Missing or empty authorization token');
    }

    // 1. Inspect protected header without verifying signature yet to determine algorithm
    let header: jose.ProtectedHeaderParameters;
    try {
      header = jose.decodeProtectedHeader(token);
    } catch {
      throw new AuthenticationError('Invalid or malformed access token');
    }

    const alg = header.alg;
    if (!alg || alg === 'none') {
      throw new AuthenticationError('Unsigned tokens are not permitted');
    }

    if (!this.allowedAlgorithms.includes(alg)) {
      throw new AuthenticationError(`Unsupported token signing algorithm: ${alg}`);
    }

    // 2. Select key resolver based on algorithm
    let keyOrJwks: Uint8Array | jose.JWTVerifyGetKey;

    if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
      if (!this.secretKey) {
        throw new AuthenticationError(
          `Token was signed with symmetric algorithm '${alg}', but no JWT secret is configured.`
        );
      }
      keyOrJwks = this.secretKey;
    } else if (alg === 'ES256' || alg === 'RS256') {
      if (!this.jwksResolver) {
        if (this.supabaseClient) {
          return this.verifyWithSupabaseAuthApi(token);
        }
        throw new AuthenticationError(
          `Token was signed with asymmetric algorithm '${alg}', but no JWKS or Supabase URL is configured.`
        );
      }
      keyOrJwks = this.jwksResolver;
    } else {
      throw new AuthenticationError(`Unsupported token signing algorithm: ${alg}`);
    }

    try {
      const { payload } = await jose.jwtVerify(token, keyOrJwks as any, {
        audience: this.audience,
        issuer: this.validIssuers,
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

      // 1. Specific signature, expiration, and claim errors
      if (error.name === 'JWTExpired') {
        throw new AuthenticationError('Access token has expired');
      }
      if (error.name === 'JWSSignatureVerificationFailed') {
        throw new AuthenticationError('Invalid token signature');
      }
      if (error.name === 'JWTClaimValidationFailed') {
        throw new AuthenticationError(`Token validation failed: ${error.message}`);
      }
      if (error.name === 'JWKSNoMatchingKey' || (error as any).code === 'ERR_JWKS_NO_MATCHING_KEY') {
        throw new AuthenticationError('Token signing key not found in identity provider JWKS');
      }
      if (error.name === 'JWKSTimeout' || (error as any).code === 'ERR_JWKS_TIMEOUT') {
        throw new AuthenticationError('Timed out fetching identity provider signing keys');
      }

      // 2. Handle network/fetch failures connecting to remote JWKS endpoint
      if (error.message?.includes('fetch failed') || error.name === 'TypeError') {
        if (this.supabaseClient) {
          try {
            return await this.verifyWithSupabaseAuthApi(token);
          } catch (authApiErr) {
            if (authApiErr instanceof AuthenticationError) throw authApiErr;
          }
        }
        throw new AuthenticationError(
          'Failed to retrieve signing keys from Supabase JWKS endpoint. Check network connectivity and SUPABASE_URL.'
        );
      }

      throw new AuthenticationError('Invalid or malformed access token');
    }
  }

  private async verifyWithSupabaseAuthApi(token: string): Promise<VerifiedTokenClaims> {
    if (!this.supabaseClient) {
      throw new AuthenticationError('Supabase client not configured for fallback verification');
    }

    const { data, error } = await this.supabaseClient.auth.getUser(token);
    if (error || !data.user) {
      throw new AuthenticationError('Invalid, expired, or revoked access token');
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    return {
      sub: data.user.id,
      email: data.user.email,
      iss: this.normalizedUrl ? `${this.normalizedUrl}/auth/v1` : 'supabase',
      aud: 'authenticated',
      iat: nowSeconds,
      exp: nowSeconds + 3600,
      user_metadata: data.user.user_metadata,
      app_metadata: data.user.app_metadata,
    };
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
