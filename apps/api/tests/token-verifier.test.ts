import { describe, it, expect, beforeEach } from 'vitest';
import * as jose from 'jose';
import request from 'supertest';
import { Express } from 'express';
import {
  AuthorizationEngine,
  AuthenticationError,
  PlatformRoles,
} from '@modular-auth/core';
import { SupabaseTokenVerifier } from '../src/services/token-verifier.js';
import { createApp } from '../src/app.js';
import { InMemoryUserService } from '../src/services/user-service.js';
import { InMemoryAuditLogger } from '../src/services/audit-logger.js';
import { InMemoryOrganizationService } from '../src/services/organization-service.js';

describe('SupabaseTokenVerifier Suite', () => {
  const supabaseUrl = 'https://mock-proj.supabase.co';
  const jwtSecret = 'test-symmetric-secret-key-at-least-32-chars-long!';

  let es256KeyPair: jose.GenerateKeyPairResult;
  let es256Jwk: jose.JWK;

  let rs256KeyPair: jose.GenerateKeyPairResult;
  let rs256Jwk: jose.JWK;

  beforeEach(async () => {
    // Generate fresh ES256 keypair (ECDSA P-256)
    es256KeyPair = await jose.generateKeyPair('ES256');
    es256Jwk = await jose.exportJWK(es256KeyPair.publicKey);
    es256Jwk.kid = 'test-es256-kid-01';
    es256Jwk.alg = 'ES256';
    es256Jwk.use = 'sig';

    // Generate fresh RS256 keypair (RSA 2048)
    rs256KeyPair = await jose.generateKeyPair('RS256');
    rs256Jwk = await jose.exportJWK(rs256KeyPair.publicKey);
    rs256Jwk.kid = 'test-rs256-kid-01';
    rs256Jwk.alg = 'RS256';
    rs256Jwk.use = 'sig';
  });

  describe('Asymmetric ES256 (JWKS) Verification (Modern Supabase Default)', () => {
    it('verifies a valid ES256 token against local JWKS successfully', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const token = await new jose.SignJWT({
        sub: 'user-es256-123',
        email: 'superadmin.modularauth@gmail.com',
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const claims = await verifier.verifyToken(token);

      expect(claims.sub).toBe('user-es256-123');
      expect(claims.email).toBe('superadmin.modularauth@gmail.com');
      expect(claims.aud).toBe('authenticated');
      expect(claims.iss).toBe(`${supabaseUrl}/auth/v1`);
    });

    it('verifies ES256 token when project URL has a trailing slash in configuration', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl: `${supabaseUrl}/`, // Trailing slash
        jwks: { keys: [es256Jwk] },
      });

      const token = await new jose.SignJWT({ sub: 'user-slash-test' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const claims = await verifier.verifyToken(token);
      expect(claims.sub).toBe('user-slash-test');
    });

    it('accepts legacy "supabase" issuer on ES256 token', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const token = await new jose.SignJWT({ sub: 'user-legacy-iss' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer('supabase')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const claims = await verifier.verifyToken(token);
      expect(claims.sub).toBe('user-legacy-iss');
      expect(claims.iss).toBe('supabase');
    });

    it('rejects ES256 token with invalid signature', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      // Sign with a different un-trusted key
      const rogueKeyPair = await jose.generateKeyPair('ES256');
      const rogueToken = await new jose.SignJWT({ sub: 'attacker-123' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(rogueKeyPair.privateKey);

      await expect(verifier.verifyToken(rogueToken)).rejects.toThrow(
        new AuthenticationError('Invalid token signature')
      );
    });

    it('rejects ES256 token when kid is missing from JWKS', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const token = await new jose.SignJWT({ sub: 'user-unknown-kid' })
        .setProtectedHeader({ alg: 'ES256', kid: 'non-existent-kid' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      await expect(verifier.verifyToken(token)).rejects.toThrow(
        new AuthenticationError('Token signing key not found in identity provider JWKS')
      );
    });

    it('rejects expired ES256 token', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const pastTimestamp = Math.floor(Date.now() / 1000) - 300;
      const expiredToken = await new jose.SignJWT({ sub: 'expired-user' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt(pastTimestamp - 3600)
        .setExpirationTime(pastTimestamp)
        .sign(es256KeyPair.privateKey);

      await expect(verifier.verifyToken(expiredToken)).rejects.toThrow(
        new AuthenticationError('Access token has expired')
      );
    });

    it('rejects ES256 token with untrusted issuer', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const evilToken = await new jose.SignJWT({ sub: 'evil-user' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer('https://attacker-project.supabase.co/auth/v1')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      await expect(verifier.verifyToken(evilToken)).rejects.toThrow(
        /Token validation failed/
      );
    });

    it('rejects ES256 token with invalid audience', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const badAudToken = await new jose.SignJWT({ sub: 'bad-aud-user' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('anon')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      await expect(verifier.verifyToken(badAudToken)).rejects.toThrow(
        /Token validation failed/
      );
    });
  });

  describe('RS256 (JWKS) Verification Support', () => {
    it('verifies a valid RS256 token against local JWKS successfully', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [rs256Jwk] },
      });

      const token = await new jose.SignJWT({ sub: 'user-rs256-456' })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-rs256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(rs256KeyPair.privateKey);

      const claims = await verifier.verifyToken(token);
      expect(claims.sub).toBe('user-rs256-456');
    });
  });

  describe('Symmetric HS256 Verification (Legacy Supabase Projects)', () => {
    it('verifies a valid HS256 token using symmetric secret', async () => {
      const verifier = new SupabaseTokenVerifier({
        jwtSecret,
        supabaseUrl,
      });

      const secretKey = new TextEncoder().encode(jwtSecret);
      const token = await new jose.SignJWT({ sub: 'user-hs256-789' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secretKey);

      const claims = await verifier.verifyToken(token);
      expect(claims.sub).toBe('user-hs256-789');
    });

    it('rejects HS256 token with invalid signature', async () => {
      const verifier = new SupabaseTokenVerifier({
        jwtSecret,
        supabaseUrl,
      });

      const wrongSecret = new TextEncoder().encode('wrong-secret-key-at-least-32-chars-long!');
      const token = await new jose.SignJWT({ sub: 'user-hs256-bad' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(wrongSecret);

      await expect(verifier.verifyToken(token)).rejects.toThrow(
        new AuthenticationError('Invalid token signature')
      );
    });

    it('throws error when HS256 token is received but no jwtSecret is configured', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const secretKey = new TextEncoder().encode(jwtSecret);
      const token = await new jose.SignJWT({ sub: 'user-hs256' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secretKey);

      await expect(verifier.verifyToken(token)).rejects.toThrow(
        /Token was signed with symmetric algorithm 'HS256', but no JWT secret is configured/
      );
    });

    it('rejects expired HS256 token', async () => {
      const verifier = new SupabaseTokenVerifier({
        jwtSecret,
        supabaseUrl,
      });

      const past = Math.floor(Date.now() / 1000) - 200;
      const secretKey = new TextEncoder().encode(jwtSecret);
      const token = await new jose.SignJWT({ sub: 'user-hs256-expired' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt(past - 3600)
        .setExpirationTime(past)
        .sign(secretKey);

      await expect(verifier.verifyToken(token)).rejects.toThrow(
        new AuthenticationError('Access token has expired')
      );
    });

    it('rejects HS256 token with wrong issuer', async () => {
      const verifier = new SupabaseTokenVerifier({
        jwtSecret,
        supabaseUrl,
      });

      const secretKey = new TextEncoder().encode(jwtSecret);
      const token = await new jose.SignJWT({ sub: 'user-hs256-wrong-iss' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('authenticated')
        .setIssuer('https://rogue.supabase.co/auth/v1')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secretKey);

      await expect(verifier.verifyToken(token)).rejects.toThrow(
        /Token validation failed/
      );
    });

    it('rejects HS256 token with wrong audience', async () => {
      const verifier = new SupabaseTokenVerifier({
        jwtSecret,
        supabaseUrl,
      });

      const secretKey = new TextEncoder().encode(jwtSecret);
      const token = await new jose.SignJWT({ sub: 'user-hs256-wrong-aud' })
        .setProtectedHeader({ alg: 'HS256' })
        .setAudience('anon')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(secretKey);

      await expect(verifier.verifyToken(token)).rejects.toThrow(
        /Token validation failed/
      );
    });
  });

  describe('Security Edge Cases & Rejection Handling', () => {
    it('rejects unsigned token with alg: none', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      const unsignedToken = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.';
      await expect(verifier.verifyToken(unsignedToken)).rejects.toThrow(
        new AuthenticationError('Unsigned tokens are not permitted')
      );
    });

    it('rejects malformed token strings', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      await expect(verifier.verifyToken('not-a-valid-jwt')).rejects.toThrow(
        new AuthenticationError('Invalid or malformed access token')
      );
    });

    it('rejects empty or whitespace authorization tokens', async () => {
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      await expect(verifier.verifyToken('')).rejects.toThrow(
        new AuthenticationError('Missing or empty authorization token')
      );
    });
  });

  describe('End-to-End API Integration with ES256 Tokens', () => {
    let app: Express;
    let userService: InMemoryUserService;
    let tokenVerifier: SupabaseTokenVerifier;

    const superadminId = 'd6d1bbef-e141-4138-ac74-987070d05527';
    const targetUserId = 'a800ea5c-667a-424a-aa09-49f6a4a8a222';

    beforeEach(() => {
      tokenVerifier = new SupabaseTokenVerifier({
        supabaseUrl,
        jwks: { keys: [es256Jwk] },
      });

      userService = new InMemoryUserService();
      userService.setUser(superadminId, 'superadmin.modularauth@gmail.com', PlatformRoles.SUPER_ADMIN);
      userService.setUser(targetUserId, 'admin.modularauth@gmail.com', null);

      app = createApp({
        tokenVerifier,
        authzEngine: new AuthorizationEngine(),
        orgService: new InMemoryOrganizationService(),
        userService,
        auditLogger: new InMemoryAuditLogger(),
      });
    });

    it('successfully processes PATCH /api/v1/platform/users/:targetUserId/role using a real ES256 token', async () => {
      const superadminToken = await new jose.SignJWT({
        sub: superadminId,
        email: 'superadmin.modularauth@gmail.com',
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const response = await request(app)
        .patch(`/api/v1/platform/users/${targetUserId}/role`)
        .set('Authorization', `Bearer ${superadminToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        message: `Platform role updated successfully for user ${targetUserId}`,
        targetUserId,
        newRole: 'admin',
      });

      // Verify the role was actually persisted in public.users
      const profile = await userService.getUserProfile(targetUserId);
      expect(profile?.platformRole).toBe('admin');
    });

    it('rejects role assignment request if ES256 token signature verification fails', async () => {
      const rogueKeyPair = await jose.generateKeyPair('ES256');
      const forgedToken = await new jose.SignJWT({
        sub: superadminId,
        email: 'superadmin.modularauth@gmail.com',
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(rogueKeyPair.privateKey);

      const response = await request(app)
        .patch(`/api/v1/platform/users/${targetUserId}/role`)
        .set('Authorization', `Bearer ${forgedToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({
        error: {
          code: 'UNAUTHENTICATED',
          message: 'Invalid token signature',
        },
      });
    });

    it('rejects role assignment request if ES256 token is expired', async () => {
      const past = Math.floor(Date.now() / 1000) - 100;
      const expiredToken = await new jose.SignJWT({
        sub: superadminId,
        email: 'superadmin.modularauth@gmail.com',
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt(past - 3600)
        .setExpirationTime(past)
        .sign(es256KeyPair.privateKey);

      const response = await request(app)
        .patch(`/api/v1/platform/users/${targetUserId}/role`)
        .set('Authorization', `Bearer ${expiredToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({
        error: {
          code: 'UNAUTHENTICATED',
          message: 'Access token has expired',
        },
      });
    });

    it('rejects role assignment request if ES256 token has wrong issuer', async () => {
      const wrongIssToken = await new jose.SignJWT({
        sub: superadminId,
        email: 'superadmin.modularauth@gmail.com',
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer('https://malicious.supabase.co/auth/v1')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const response = await request(app)
        .patch(`/api/v1/platform/users/${targetUserId}/role`)
        .set('Authorization', `Bearer ${wrongIssToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
      expect(response.body.error.message).toContain('Token validation failed');
    });

    it('rejects role assignment request if ES256 token has wrong audience', async () => {
      const wrongAudToken = await new jose.SignJWT({
        sub: superadminId,
        email: 'superadmin.modularauth@gmail.com',
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('anon')
        .setIssuer(`${supabaseUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const response = await request(app)
        .patch(`/api/v1/platform/users/${targetUserId}/role`)
        .set('Authorization', `Bearer ${wrongAudToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('UNAUTHENTICATED');
      expect(response.body.error.message).toContain('Token validation failed');
    });
  });

  describe('Environment Configuration & Project URL Validation', () => {
    it('defaults SUPABASE_URL to the configured Supabase project URL', async () => {
      const { envSchema } = await import('../src/config/env.js');
      const parsed = envSchema.parse({});
      expect(parsed.SUPABASE_URL).toBe('https://vsllykwuqqmbitxvpuod.supabase.co');
    });

    it('validates a token signed for the project URL https://vsllykwuqqmbitxvpuod.supabase.co', async () => {
      const projUrl = 'https://vsllykwuqqmbitxvpuod.supabase.co';
      const verifier = new SupabaseTokenVerifier({
        supabaseUrl: projUrl,
        jwks: { keys: [es256Jwk] },
      });

      const token = await new jose.SignJWT({ sub: 'user-project-valid' })
        .setProtectedHeader({ alg: 'ES256', kid: 'test-es256-kid-01' })
        .setAudience('authenticated')
        .setIssuer(`${projUrl}/auth/v1`)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(es256KeyPair.privateKey);

      const claims = await verifier.verifyToken(token);
      expect(claims.sub).toBe('user-project-valid');
      expect(claims.iss).toBe(`${projUrl}/auth/v1`);
    });
  });
});
