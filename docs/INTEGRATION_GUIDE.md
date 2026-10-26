# Modular Auth Foundation: Integration Guide

This guide explains how to integrate **Modular Auth Foundation** into external Node.js/Express backends, React frontends, or MERN stack applications.

---

## 1. Overview of Packages

The foundation consists of two architectural tiers:

1. **`@modular-auth/core`**: Framework-agnostic TypeScript core library.
   - Contains role definitions, permission matrix, authorization engine, domain errors, and types.
   - Zero runtime framework dependencies (depends only on `zod`).
   - Usable in any Node.js service, worker, or backend framework.
2. **`@modular-auth/api`**: Production-ready Express API reference implementation.
   - Contains token verification (`jose` JWKS + symmetric fallback), user resolution, tenant isolation middleware, rate limiters, and platform endpoints.

---

## 2. Integrating `@modular-auth/core` in a Node.js Application

### Installation

If using a monorepo workspace:
```json
{
  "dependencies": {
    "@modular-auth/core": "*"
  }
}
```

Or copy the compiled distribution or package into your service.

### Evaluating Roles & Permissions

```typescript
import {
  AuthorizationEngine,
  defaultPermissionsMatrix,
  PlatformRole,
  OrgRole
} from '@modular-auth/core';

// Initialize the authorization engine with standard or custom matrix
const authEngine = new AuthorizationEngine(defaultPermissionsMatrix);

// 1. Evaluate a platform-level permission
const canManageUsers = authEngine.hasPlatformPermission(
  'superadmin', // User's authoritative platform_role
  'platform:users:update_role'
);
// true

const regularAdminCanUpdate = authEngine.hasPlatformPermission(
  'admin',
  'platform:users:update_role'
);
// false (Only superadmin and founder can assign platform roles)

// 2. Evaluate an organization-level permission
const canDeleteProject = authEngine.hasOrgPermission(
  'manager', // User's membership role in target org
  'projects:delete'
);
// false (Only business_owner and leader can delete projects)
```

---

## 3. Integrating Authentication & Middleware in Express

### Option A: One-Line Express Plugin Integration (Recommended)

Mount Modular Auth Foundation into an existing Express application with zero boilerplate:

```typescript
import express from 'express';
import { createModularAuthPlugin } from '@modular-auth/api';

const app = express();

const authPlugin = createModularAuthPlugin({
  supabaseUrl: process.env.SUPABASE_URL!,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY, // Optional: for authoritative DB queries
  corsOrigin: 'http://localhost:5173',
});

// Mount all security middleware, health, platform, and tenant routes
app.use('/auth', authPlugin);
```

### Option B: Granular Middleware & Services Integration

If your application has its own existing route architecture, you can import and compose individual middlewares and services directly:

#### Setting Up Token Verification

In your Express application, initialize the `SupabaseTokenVerifier`:

```typescript
import { SupabaseTokenVerifier } from '@modular-auth/api';

const tokenVerifier = new SupabaseTokenVerifier({
  supabaseUrl: process.env.SUPABASE_URL!, // e.g. https://xyz.supabase.co
  jwtSecret: process.env.SUPABASE_JWT_SECRET, // Optional for ES256 JWKS
  clockToleranceSeconds: 10
});

// Verify a Bearer token:
const tokenClaims = await tokenVerifier.verifyToken(rawBearerToken);
console.log(`Authenticated user ID: ${tokenClaims.sub}`);
```

#### Applying Authentication & Role Guards

```typescript
import express from 'express';
import {
  authenticate,
  requirePlatformRole,
  requireOrgMembership,
  SupabaseUserService,
} from '@modular-auth/api';

const app = express();
const userService = new SupabaseUserService({
  supabaseUrl: process.env.SUPABASE_URL!,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
});

// 1. Authenticate bearer token and resolve authoritative database profile
const authGuard = authenticate({
  tokenVerifier,
  userResolver: async (userId: string) => {
    return await userService.getUserProfile(userId);
  }
});

// 2. Protect sensitive platform routes (Superadmin / Founder only)
app.patch(
  '/api/v1/platform/users/:targetUserId/role',
  authGuard,
  requirePlatformRole(['superadmin', 'founder']),
  async (req, res) => {
    // Controller logic...
  }
);

// 3. Protect multi-tenant organization routes
app.get(
  '/api/v1/organizations/:orgId/projects',
  authenticate,
  createRequireOrgMembershipMiddleware({
    orgService,
    orgIdParam: 'orgId' // Extracts :orgId from route
  }),
  async (req, res) => {
    // req.tenant contains verified membership:
    // { organizationId: '...', role: 'business_owner', ... }
  }
);
```

---

## 4. Integrating in a React Frontend Client

### Obtaining Access Tokens with Supabase Client

In your React application:

```typescript
import { createClient } from '@supabase/supabase-js';

export const supabase = createClient(
  process.env.VITE_SUPABASE_URL!,
  process.env.VITE_SUPABASE_ANON_KEY! // Public client key
);

// Sign in with email and password
export async function loginUser(email: string, password: string) {
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password
  });
  if (error) throw error;
  return data.session?.access_token;
}
```

### Calling Protected Backend Endpoints

Attach the session access token to API calls:

```typescript
async function fetchProtectedResource(path: string) {
  const { data: { session } } = await supabase.auth.getSession();
  const token = session?.access_token;

  if (!token) {
    throw new Error('User is not authenticated');
  }

  const response = await fetch(`http://localhost:4000${path}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const errorBody = await response.json();
    throw new Error(errorBody.error?.message || 'Request failed');
  }

  return await response.json();
}
```

### Client-Side Role UX vs. Backend Enforcement

- **Client Rule**: Client-side role checks are strictly for UX (hiding tabs or disabled buttons).
- **Backend Rule**: The backend API never trusts claims sent from the client; it re-validates the token against JWKS and resolves `public.users.platform_role` on every privileged request.

---

## 5. Security Checklist for Consumers

1. **Service-Role Key Isolation**: Never expose `SUPABASE_SERVICE_ROLE_KEY` to client apps, frontend Vite/Webpack bundles, or mobile applications.
2. **Authoritative Resolution**: Always resolve platform roles from the database (`public.users`), not from client-editable user metadata in the JWT.
3. **Tenant Boundary**: Always verify tenant membership through `requireOrgMembership` before executing queries against tenant data.
4. **Fail Closed**: Handle unknown roles, disabled accounts, and missing profiles by rejecting requests (`401` or `403`).
