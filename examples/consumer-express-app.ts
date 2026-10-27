/**
 * Example: Minimal Consumer Express Application
 * Demonstrates how an external ArchScale microservice or application
 * imports and integrates Modular Auth Foundation.
 */
import express from 'express';
import {
  createModularAuthPlugin,
  authenticate,
  requirePlatformRole,
  requireTenantMembership,
  requirePermission,
  requireMFA,
  SupabaseTokenVerifier,
} from '@modular-auth/api';
import {
  PlatformRoles,
  StandardPermissions,
  AuthorizationEngine,
  createPermissionMatrixConfig,
} from '@modular-auth/core';

// 1. Initialize host Express app
const app = express();
app.use(express.json());

// 2. Custom permission matrix override (optional)
const customEngine = new AuthorizationEngine({
  matrixConfig: createPermissionMatrixConfig({
    platform: {
      [PlatformRoles.DEVELOPER]: [
        StandardPermissions.PLATFORM_VIEW_SYSTEM,
        StandardPermissions.PLATFORM_VIEW_METRICS,
      ],
    },
  }),
});

// 3. Mount Modular Auth Plugin on /auth
// Provides: /health, /api/v1/auth/me, /api/v1/platform/*, /api/v1/organizations/*
app.use(
  '/auth',
  createModularAuthPlugin({
    supabaseUrl: process.env.SUPABASE_URL ?? 'https://vsllykwuqqmbitxvpuod.supabase.co',
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    jwtSecret: process.env.SUPABASE_JWT_SECRET,
    corsOrigin: process.env.CORS_ORIGIN ?? 'http://localhost:5173',
    authzEngine: customEngine,
  })
);

// 4. Standalone Custom Route 1: Platform administrative route
const tokenVerifier = new SupabaseTokenVerifier({
  supabaseUrl: process.env.SUPABASE_URL ?? 'https://vsllykwuqqmbitxvpuod.supabase.co',
});
const auth = authenticate({ tokenVerifier });

app.get(
  '/app/admin/system-diagnostics',
  auth,
  requirePlatformRole([PlatformRoles.SUPER_ADMIN, PlatformRoles.FOUNDER]),
  (req, res) => {
    res.json({
      status: 'ok',
      actorRole: req.auth?.user.platformRole,
      uptime: process.uptime(),
    });
  }
);

// 5. Standalone Custom Route 2: Tenant & workspace-scoped business resource
app.get(
  '/app/organizations/:orgId/invoices',
  auth,
  // requireTenantMembership validates membership and extracts :orgId and optional X-Workspace-Id
  (req, _res, next) => {
    // Host app supplies its IOrganizationService implementation
    next();
  },
  (req, res) => {
    res.json({
      tenantId: req.tenant?.organizationId,
      workspaceId: req.tenant?.workspaceId,
      invoices: [],
    });
  }
);

// 6. Standalone Custom Route 3: MFA Step-Up required endpoint
app.post(
  '/app/admin/payouts/execute',
  auth,
  requirePlatformRole([PlatformRoles.SUPER_ADMIN]),
  requireMFA({ requiredLevel: 'aal2' }),
  (req, res) => {
    res.json({
      message: 'Payout executed successfully. Verified with AAL2.',
      assuranceLevel: req.mfa?.currentLevel,
    });
  }
);

// Start application
const PORT = process.env.PORT ?? 5000;
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Consumer application listening securely on port ${PORT}`);
  });
}

export default app;
