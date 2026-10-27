import { SupabaseClient } from '@supabase/supabase-js';
import {
  IMFAProvider,
  MFAFactor,
  MFAFactorType,
  MFAEnrollmentResult,
  MFAChallenge,
  MFAVerificationResult,
  ConfigurationError,
} from '@modular-auth/core';

export interface SupabaseMFAProviderOptions {
  readonly supabaseClient?: SupabaseClient;
}

/**
 * Production implementation integrating with Supabase Auth MFA.
 */
export class SupabaseMFAProvider implements IMFAProvider {
  private readonly supabase?: SupabaseClient;

  constructor(options: SupabaseMFAProviderOptions = {}) {
    this.supabase = options.supabaseClient;
  }

  public async listFactors(_userId: string): Promise<readonly MFAFactor[]> {
    if (!this.supabase) {
      throw new ConfigurationError('Supabase client is required for MFA operations');
    }

    const { data, error } = await this.supabase.auth.mfa.listFactors();
    if (error || !data) {
      return [];
    }

    const factors = data.all ?? [];
    return factors.map((factor) => ({
      id: factor.id,
      factorType: factor.factor_type as MFAFactorType,
      status: factor.status as 'verified' | 'unverified',
      friendlyName: factor.friendly_name,
      createdAt: new Date(factor.created_at),
      updatedAt: factor.updated_at ? new Date(factor.updated_at) : undefined,
    }));
  }

  public async enrollFactor(
    _userId: string,
    factorType: MFAFactorType,
    friendlyName?: string
  ): Promise<MFAEnrollmentResult> {
    if (!this.supabase) {
      throw new ConfigurationError('Supabase client is required for MFA operations');
    }

    if (factorType !== 'totp') {
      throw new Error(`Unsupported MFA factor type: ${factorType}`);
    }

    const { data, error } = await this.supabase.auth.mfa.enroll({
      factorType: 'totp',
      friendlyName: friendlyName ?? 'Authenticator App',
    });

    if (error || !data) {
      throw new Error(`Failed to enroll MFA factor: ${error?.message ?? 'Unknown error'}`);
    }

    return {
      factorId: data.id,
      factorType: 'totp',
      totpUri: data.totp?.uri,
      secret: data.totp?.secret,
      qrCode: data.totp?.qr_code,
    };
  }

  public async challengeFactor(factorId: string): Promise<MFAChallenge> {
    if (!this.supabase) {
      throw new ConfigurationError('Supabase client is required for MFA operations');
    }

    const { data, error } = await this.supabase.auth.mfa.challenge({ factorId });
    if (error || !data) {
      throw new Error(`Failed to issue MFA challenge: ${error?.message ?? 'Unknown error'}`);
    }

    return {
      id: data.id,
      factorId,
      createdAt: new Date(),
      expiresAt: new Date(data.expires_at * 1000),
    };
  }

  public async verifyChallenge(challengeId: string, code: string): Promise<MFAVerificationResult> {
    if (!this.supabase) {
      throw new ConfigurationError('Supabase client is required for MFA operations');
    }

    // Verify code against challenge
    const { data, error } = await this.supabase.auth.mfa.verify({
      factorId: challengeId,
      challengeId,
      code,
    });

    if (error || !data) {
      return {
        verified: false,
        aal: 'aal1',
        error: error?.message ?? 'Invalid MFA verification code',
      };
    }

    return {
      verified: true,
      aal: 'aal2',
    };
  }

  public async unenrollFactor(_userId: string, factorId: string): Promise<void> {
    if (!this.supabase) {
      throw new ConfigurationError('Supabase client is required for MFA operations');
    }

    const { error } = await this.supabase.auth.mfa.unenroll({ factorId });
    if (error) {
      throw new Error(`Failed to unenroll MFA factor: ${error.message}`);
    }
  }
}

/**
 * In-memory MFA provider for testing, local simulation, and headless integration tests.
 */
export class InMemoryMFAProvider implements IMFAProvider {
  private readonly factors = new Map<string, MFAFactor[]>();
  private readonly challenges = new Map<string, { factorId: string; expiresAt: Date }>();
  private validCode = '123456';

  public setValidCode(code: string): void {
    this.validCode = code;
  }

  public async listFactors(userId: string): Promise<readonly MFAFactor[]> {
    return this.factors.get(userId) ?? [];
  }

  public async enrollFactor(
    userId: string,
    factorType: MFAFactorType,
    friendlyName?: string
  ): Promise<MFAEnrollmentResult> {
    const factorId = `mfa-factor-${Date.now()}`;
    const newFactor: MFAFactor = {
      id: factorId,
      userId,
      factorType,
      status: 'unverified',
      friendlyName: friendlyName ?? 'Test Authenticator',
      createdAt: new Date(),
    };

    const existing = this.factors.get(userId) ?? [];
    this.factors.set(userId, [...existing, newFactor]);

    return {
      factorId,
      factorType,
      totpUri: `otpauth://totp/ArchScale:user?secret=JBSWY3DPEHPK3PXP&issuer=ArchScale`,
      secret: 'JBSWY3DPEHPK3PXP',
    };
  }

  public async challengeFactor(factorId: string): Promise<MFAChallenge> {
    const challengeId = `mfa-chal-${Date.now()}`;
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    this.challenges.set(challengeId, { factorId, expiresAt });

    return {
      id: challengeId,
      factorId,
      createdAt: new Date(),
      expiresAt,
    };
  }

  public async verifyChallenge(challengeId: string, code: string): Promise<MFAVerificationResult> {
    const challenge = this.challenges.get(challengeId);
    if (!challenge) {
      return { verified: false, aal: 'aal1', error: 'Challenge not found or expired' };
    }

    if (Date.now() > challenge.expiresAt.getTime()) {
      return { verified: false, aal: 'aal1', error: 'Challenge expired' };
    }

    if (code !== this.validCode) {
      return { verified: false, aal: 'aal1', error: 'Invalid verification code' };
    }

    // Mark factor as verified
    for (const [userId, userFactors] of this.factors.entries()) {
      const match = userFactors.find((f) => f.id === challenge.factorId);
      if (match) {
        this.factors.set(
          userId,
          userFactors.map((f) => (f.id === challenge.factorId ? { ...f, status: 'verified' } : f))
        );
      }
    }

    return {
      verified: true,
      aal: 'aal2',
    };
  }

  public async unenrollFactor(userId: string, factorId: string): Promise<void> {
    const existing = this.factors.get(userId) ?? [];
    this.factors.set(
      userId,
      existing.filter((f) => f.id !== factorId)
    );
  }
}
