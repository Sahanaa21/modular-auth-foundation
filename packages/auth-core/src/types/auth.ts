import { PlatformRole } from './roles.js';

/**
 * Standardized user identity extracted after successful authentication.
 */
export interface UserIdentity {
  /** Unique user identifier (e.g. Supabase auth.users UUID) */
  readonly id: string;
  /** Primary verified or registered email */
  readonly email: string;
  /** Whether user's email address has been verified */
  readonly isEmailVerified: boolean;
  /** Optional platform-level role assigned to this user */
  readonly platformRole?: PlatformRole | null;
  /** Provider-supplied custom user metadata */
  readonly userMetadata?: Record<string, unknown>;
  /** Timestamp of account creation */
  readonly createdAt: Date;
}

/**
 * Session tokens returned on successful login or refresh.
 */
export interface SessionTokens {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly expiresIn: number;
  readonly tokenType: 'Bearer';
}

/**
 * Decoded and verified JWT claims.
 */
export interface VerifiedTokenClaims {
  /** Subject identifier (user UUID) */
  readonly sub: string;
  /** User email */
  readonly email?: string;
  /** Token issuer (e.g., Supabase Auth URL) */
  readonly iss: string;
  /** Token audience */
  readonly aud: string;
  /** Issued at (Unix timestamp seconds) */
  readonly iat: number;
  /** Expiration time (Unix timestamp seconds) */
  readonly exp: number;
  /** Raw claims for provider-specific attributes */
  readonly [key: string]: unknown;
}

/**
 * Standard credentials for password-based authentication.
 */
export interface PasswordCredentials {
  readonly email: string;
  readonly password: string;
}

/**
 * Registration payload.
 */
export interface SignUpPayload extends PasswordCredentials {
  readonly fullName?: string;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Password reset request payload.
 */
export interface PasswordResetPayload {
  readonly email: string;
  readonly redirectTo?: string;
}

/**
 * Password update payload for recovery flows.
 */
export interface PasswordUpdatePayload {
  readonly newPassword: string;
  readonly accessToken?: string;
}

/**
 * Abstract backend token verification interface.
 * Implemented using Supabase JWT verification (JWKS / JWT Secret) or Supabase Auth API.
 */
export interface ITokenVerifier {
  /**
   * Verifies the provided raw Bearer token and returns decoded claims.
   * Throws an authentication error if expired, invalid, or forged.
   */
  verifyToken(token: string): Promise<VerifiedTokenClaims>;
}

/**
 * Abstract provider interface for authentication lifecycle operations.
 * Allows decoupling application logic from Supabase-specific client code.
 */
export interface IAuthProvider {
  /** Register a new user */
  signUp(payload: SignUpPayload): Promise<{ user: UserIdentity; tokens?: SessionTokens }>;

  /** Authenticate with email and password */
  signInWithPassword(credentials: PasswordCredentials): Promise<{ user: UserIdentity; tokens: SessionTokens }>;

  /** Invalidate the current session and logout */
  signOut(accessToken: string): Promise<void>;

  /** Refresh an expired access token using a refresh token */
  refreshToken(refreshToken: string): Promise<SessionTokens>;

  /** Initiate password reset recovery email */
  resetPasswordForEmail(payload: PasswordResetPayload): Promise<void>;

  /** Update password after following reset flow */
  updatePassword(payload: PasswordUpdatePayload): Promise<void>;

  /** Fetch current user by active access token */
  getUserByToken(accessToken: string): Promise<UserIdentity>;
}
