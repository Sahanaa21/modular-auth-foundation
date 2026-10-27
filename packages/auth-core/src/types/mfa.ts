/**
 * Authentication Assurance Level (AAL) defined by NIST SP 800-63B
 * and implemented natively by Supabase Auth.
 *
 * - AAL1: Single-factor authentication (email/password, OAuth, Magic Link)
 * - AAL2: Multi-factor authentication (AAL1 + verified second factor like TOTP)
 */
export type AALLevel = 'aal1' | 'aal2';

/**
 * MFA Factor types supported by the foundation.
 */
export type MFAFactorType = 'totp' | 'phone';

/**
 * MFA Factor verification status.
 */
export type MFAFactorStatus = 'unverified' | 'verified';

/**
 * Registered MFA factor associated with a user account.
 */
export interface MFAFactor {
  readonly id: string;
  readonly userId?: string;
  readonly factorType: MFAFactorType;
  readonly status: MFAFactorStatus;
  readonly friendlyName?: string;
  readonly createdAt: Date;
  readonly updatedAt?: Date;
}

/**
 * TOTP / Authenticator App factor enrollment response.
 */
export interface MFAEnrollmentResult {
  readonly factorId: string;
  readonly factorType: MFAFactorType;
  readonly totpUri?: string;
  readonly secret?: string;
  readonly qrCode?: string;
}

/**
 * Active MFA challenge issued for verification.
 */
export interface MFAChallenge {
  readonly id: string;
  readonly factorId: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
}

/**
 * Result of an MFA challenge verification attempt.
 */
export interface MFAVerificationResult {
  readonly verified: boolean;
  readonly aal: AALLevel;
  readonly error?: string;
}

/**
 * Application or endpoint MFA enforcement policy:
 * - 'optional': User may enroll; not required for access
 * - 'required': User must enroll and authenticate with AAL2 to access the system
 * - 'step_up': Specific high-privilege endpoints require active AAL2 session assurance
 */
export type MFAPolicy = 'optional' | 'required' | 'step_up';

/**
 * MFA session context extracted from verified JWT claims ('aal' and 'amr').
 */
export interface MFAContext {
  /** The current assurance level of the active access token */
  readonly currentLevel: AALLevel;
  /** Whether the session satisfies AAL2 requirements */
  readonly isAAL2: boolean;
  /** Authentication Methods References (e.g. ['password', 'totp']) */
  readonly amr: readonly string[];
  /** Optional list of enrolled factors for the user */
  readonly enrolledFactors?: readonly MFAFactor[];
}

/**
 * Abstract MFA Provider interface.
 * Implemented by Supabase Auth MFA or provider adapters.
 */
export interface IMFAProvider {
  /**
   * Lists all registered MFA factors for a user.
   */
  listFactors(userId: string): Promise<readonly MFAFactor[]>;

  /**
   * Initiates enrollment for a new factor (e.g., generates TOTP secret and QR URI).
   */
  enrollFactor(userId: string, factorType: MFAFactorType, friendlyName?: string): Promise<MFAEnrollmentResult>;

  /**
   * Creates a challenge against an enrolled factor.
   */
  challengeFactor(factorId: string): Promise<MFAChallenge>;

  /**
   * Verifies the user-supplied code against an issued challenge.
   */
  verifyChallenge(challengeId: string, code: string): Promise<MFAVerificationResult>;

  /**
   * Removes/unenrolls an MFA factor from a user account.
   */
  unenrollFactor(userId: string, factorId: string): Promise<void>;
}
