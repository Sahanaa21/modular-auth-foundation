import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  AALLevel,
  MFAVerificationRequiredError,
  AuthenticationError,
  MFAContext,
} from '@modular-auth/core';

export interface RequireMFAOptions {
  /** The minimum Authentication Assurance Level required. Defaults to 'aal2' */
  readonly requiredLevel?: AALLevel;
}

declare global {
  namespace Express {
    interface Request {
      mfa?: MFAContext;
    }
  }
}

/**
 * Middleware enforcing Multi-Factor Authentication (AAL2) on protected or privileged endpoints.
 *
 * Inspects verified JWT claims issued by Supabase Auth:
 * - `aal`: 'aal1' (single-factor) or 'aal2' (multi-factor)
 * - `amr`: array of authentication method references, e.g. ['password', 'totp']
 *
 * Fails closed with 403 MFA_REQUIRED if the session has not achieved AAL2 assurance.
 */
export function requireMFA(options: RequireMFAOptions = {}): RequestHandler {
  const requiredLevel = options.requiredLevel ?? 'aal2';

  return (req: Request, _res: Response, next: NextFunction): void => {
    try {
      if (!req.auth?.claims) {
        throw new AuthenticationError('Authentication required before evaluating MFA assurance');
      }

      const claims = req.auth.claims;
      const rawAAL = typeof claims['aal'] === 'string' ? claims['aal'] : 'aal1';
      const amrRaw = Array.isArray(claims['amr']) ? claims['amr'] : [];
      const amr: readonly string[] = amrRaw.map((entry) =>
        typeof entry === 'object' && entry !== null && 'method' in entry
          ? String((entry as { method: unknown }).method)
          : String(entry)
      );

      const hasMfaMethod = amr.includes('totp') || amr.includes('mfa');
      const currentLevel: AALLevel = rawAAL === 'aal2' || hasMfaMethod ? 'aal2' : 'aal1';
      const isAAL2 = currentLevel === 'aal2';

      // Attach MFA Context to Request
      req.mfa = {
        currentLevel,
        isAAL2,
        amr,
      };

      if (requiredLevel === 'aal2' && !isAAL2) {
        throw new MFAVerificationRequiredError(
          'Multi-factor authentication (AAL2) required for this privileged operation',
          {
            currentAssuranceLevel: currentLevel,
            requiredAssuranceLevel: requiredLevel,
          }
        );
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}
