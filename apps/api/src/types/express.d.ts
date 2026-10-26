import { AuthContext, TenantContext } from '@modular-auth/core';

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
      tenant?: TenantContext;
    }
  }
}

export {};
