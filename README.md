# Modular Auth Foundation

Enterprise-grade, reusable authentication and authorization foundation for Node.js and TypeScript backends, backed by Supabase Auth and PostgreSQL.

Designed for review and production adoption at ArchScale.

---

## 1. System Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │              Client Application              │
                      │  (Postman / cURL / Web / Mobile Frontend)    │
                      └──────────────────────┬───────────────────────┘
                                             │
                       HTTPS Bearer JWT Token│ (ES256 / JWKS or HS256)
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │          Express API (@modular-auth/api)     │
                      │  Port 4000 (configurable via PORT)           │
                      ├──────────────────────────────────────────────┤
                      │ [1] Security Headers (Helmet CSP/HSTS)       │
                      │ [2] Strict CORS Origin Allowlist             │
                      │ [3] Rate Limiting (Global + Sensitive Auth)  │
                      │ [4] Bearer Token Extraction                  │
                      │ [5] SupabaseTokenVerifier (jose / JWKS / alg)│
                      │ [6] Authoritative User Hydration             │
                      │     (public.users via SupabaseServiceRole)   │
                      │ [7] Role Guard (Platform vs Org RBAC/PBAC)   │
                      │ [8] Audit Logging (Sanitized Security Events)│
                      └──────────────────────┬───────────────────────┘
                                             │
                     Direct SQL / Service-Role Connection (PostgREST)
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │             Supabase PostgreSQL              │
                      ├──────────────────────────────────────────────┤
                      │ • auth.users (Credentials & Session Tokens)  │
                      │ • public.users (Authoritative Platform Roles)│
                      │ • public.organizations & memberships         │
                      │ • public.audit_logs (Immutable Audit Trail)  │
                      │ • Security Definer Triggers (Anti-escalation)│
                      │ • Row Level Security (RLS) Fail-Closed       │
                      └──────────────────────────────────────────────┘
```

### Key Architectural Tenets
1. **Never Trust Client Claims for Platform Roles**: JWT claims and client-editable metadata are never accepted as the authority for privileged operations. Roles are authoritatively verified against `public.users.platform_role`.
2. **Asymmetric Token Verification (ES256 / JWKS)**: Modern Supabase projects sign tokens using asymmetric elliptic curve keys (`ES256`). The verifier dynamically resolves public keys from Supabase's `.well-known/jwks.json` endpoint with caching and rotation, while maintaining backward compatibility with symmetric `HS256` secrets.
3. **Defense-in-Depth Role Protection**: PostgreSQL triggers and column-level privileges prevent self-escalation even if SQL credentials are leak-tested.
4. **Concurrency-Safe One-Time Bootstrap**: Initial Superadmin provisioning uses PostgreSQL transaction-scoped advisory locks (`pg_advisory_xact_lock`) ensuring exactly one Superadmin can be initialized before permanent locking.
5. **Separation of Concerns**: Platform roles (`superadmin`, `founder`, `admin`, etc.) are decoupled from tenant/organization roles (`business_owner`, `manager`, `collaborator`, etc.).

---

## 2. Monorepo Structure

```
modular-auth-foundation/
├── apps/
│   ├── api/                  # Express.js REST API with full security middleware
│   │   ├── src/
│   │   │   ├── config/       # Environment loading & validation
│   │   │   ├── middleware/   # Auth, role, permission, rate-limiting, error handling
│   │   │   ├── services/     # Token verifier, user service, org service, audit logger
│   │   │   ├── app.ts        # Route registry & middleware wiring
│   │   │   └── index.ts      # HTTP server entry point (Port 4000)
│   │   └── tests/            # Automated integration & unit tests
│   └── web/                  # Dedicated directory for frontend client integration
├── packages/
│   └── auth-core/            # Framework-agnostic TypeScript core library
│       └── src/
│           ├── types/        # TypeScript contracts (roles, permissions, auth, context)
│           ├── engine/       # Dual-tier authorization engine
│           └── errors/       # Fail-closed domain error hierarchy (AuthBaseError)
├── docs/
│   ├── ARCHITECTURE.md       # Complete architectural specification & trust boundaries
│   ├── DATABASE_SCHEMA.sql   # Complete PostgreSQL schema, triggers, and RLS policies
│   ├── ADMIN_PROVISIONING.md # Step-by-step administrative provisioning guide
│   └── migrations/           # Versioned, reviewed PostgreSQL migrations
└── package.json              # Monorepo scripts (build, test, typecheck, dev, start)
```

---

## 3. Prerequisites

- **Node.js**: `v20.0.0` or higher (`node -v`)
- **npm**: `v10.0.0` or higher (`npm -v`)
- **Supabase Project**: A deployed Supabase project (e.g., `https://vsllykwuqqmbitxvpuod.supabase.co`)

---

## 4. Installation & Environment Configuration

### Step 1: Install Dependencies
From the repository root:
```bash
npm install
```

### Step 2: Configure Environment Variables
Copy `.env.example` to `.env` in the repository root:
```bash
cp .env.example .env
```

Edit `.env` with your values:
```ini
# Server Configuration
PORT=4000
NODE_ENV=development

# Allowed Origins for CORS (comma-separated)
CORS_ORIGIN=http://localhost:5173

# Supabase Project URL
SUPABASE_URL=https://vsllykwuqqmbitxvpuod.supabase.co

# Supabase Backend Service-Role Key (CRITICAL: Required for authoritative database queries)
# Found in: Supabase Dashboard -> Project Settings -> API -> Project API keys -> service_role secret
SUPABASE_SERVICE_ROLE_KEY=your_actual_service_role_key_here

# Supabase JWT Secret (Optional if your project signs with ES256/RS256 via JWKS)
SUPABASE_JWT_SECRET=your_jwt_secret_if_using_hs256

# Rate Limiting Configuration
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
AUTH_RATE_LIMIT_MAX_REQUESTS=10
```

> [!IMPORTANT]
> The `SUPABASE_SERVICE_ROLE_KEY` is a confidential server-side credential that bypasses Row-Level Security for administrative queries. Never commit this key to Git or expose it to frontend code.

---

## 5. Development & Production Execution

### Development Mode (with Live Hot-Reloading via `tsx watch`):
```bash
npm run dev
```
The API will start at `http://localhost:4000`.

### Typecheck All Workspaces:
```bash
npm run typecheck
```

### Run All Automated Tests:
```bash
npm test
```

### Build Production Bundles (TypeScript compilation to JavaScript):
```bash
npm run build
```

### Run Compiled Production Server:
```bash
npm start
```

---

## 6. Supabase Database Setup & Migrations

If configuring a new Supabase project or verifying database schema:

1. Open the **Supabase Dashboard &rarr; SQL Editor**.
2. Run the baseline schema: [`docs/DATABASE_SCHEMA.sql`](docs/DATABASE_SCHEMA.sql).
3. Apply the initial superadmin bootstrap migration: [`docs/migrations/001_bootstrap_initial_superadmin.sql`](docs/migrations/001_bootstrap_initial_superadmin.sql).

This provisions:
- `public.users` (linked to `auth.users` via foreign key and sync trigger)
- `public.organizations` & `public.organization_memberships`
- `public.projects` (tenant isolation sample resource)
- `public.audit_logs` (immutable security log store)
- `public.protect_platform_role_escalation()` trigger function (with `SET search_path = public, auth, pg_temp;`)
- `public.bootstrap_initial_superadmin(UUID)` atomic bootstrap function

---

## 7. How to Test Role Assignment End-to-End

### Step 1: Obtain a Superadmin Access Token
Use cURL or Postman to sign in with the Superadmin credentials:
```bash
curl -X POST 'https://vsllykwuqqmbitxvpuod.supabase.co/auth/v1/token?grant_type=password' \
  -H 'apikey: <YOUR_SUPABASE_ANON_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "superadmin.modularauth@gmail.com",
    "password": "<SUPERADMIN_PASSWORD>"
  }'
```
Extract the `access_token` from the JSON response.

### Step 2: Call the Role Assignment Endpoint
Target: `PATCH /api/v1/platform/users/:targetUserId/role`

#### cURL Request:
```bash
curl -X PATCH 'http://localhost:4000/api/v1/platform/users/a800ea5c-667a-424a-aa09-49f6a4a8a222/role' \
  -H 'Authorization: Bearer <SUPERADMIN_ACCESS_TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "admin"
  }'
```

#### Postman Request Details:
1. **Method**: `PATCH`
2. **URL**: `http://localhost:4000/api/v1/platform/users/a800ea5c-667a-424a-aa09-49f6a4a8a222/role`
3. **Headers Tab**:
   - `Authorization`: `Bearer <SUPERADMIN_ACCESS_TOKEN>`
   - `Content-Type`: `application/json`
4. **Body Tab**:
   - Select **raw** &rarr; **JSON**
   ```json
   {
     "role": "admin"
   }
   ```
5. Click **Send**.

#### Expected Responses:

| Condition | HTTP Status | Response Payload |
| :--- | :--- | :--- |
| **Success** (Superadmin assigns allowed role) | `200 OK` | `{"message": "Platform role updated successfully...", "targetUserId": "...", "newRole": "admin"}` |
| **Self-Modification Attempt** (Superadmin updates their own ID) | `403 Forbidden` | `{"error": {"code": "FORBIDDEN", "message": "Self-modification of platform role is forbidden to prevent administrative lockout"}}` |
| **Insufficient Privilege** (Admin or normal user attempts update) | `403 Forbidden` | `{"error": {"code": "FORBIDDEN", "message": "Platform access denied. Required role in [superadmin, founder]..."}}` |
| **Unauthenticated** (Missing or invalid token) | `401 Unauthorized` | `{"error": {"code": "UNAUTHENTICATED", "message": "Missing Authorization header..."}}` |
| **Invalid Role Name** (e.g. `role: "god_mode"`) | `400 Bad Request` | `{"error": {"code": "VALIDATION_ERROR", "message": "Invalid request input"}}` |
| **Invalid UUID Format** (e.g. not RFC 4122) | `400 Bad Request` | `{"error": {"code": "VALIDATION_ERROR", "message": "Invalid target user ID format"}}` |
| **Target User Missing** | `404 Not Found` | `{"error": {"code": "NOT_FOUND", "message": "User '...' not found"}}` |
| **Database Connection Failure** | `500 Server Error` | `{"error": {"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected internal server error occurred"}}` |

---

## 8. Security Design & Audit Verification

- **Audit Events**: All role updates and denied privilege attempts are automatically dispatched to `IAuditLogger` (`authz:platform_role_updated`) with sanitized metadata (no passwords or tokens).
- **Search Path Hardening**: All `SECURITY DEFINER` PostgreSQL functions are pinned with `SET search_path = public, auth, pg_temp;` to mitigate search path hijacking.
- **Fail-Closed Default**: Unknown roles, missing database records, or unhandled exceptions fail closed with safe error responses without leaking internal schema or stack traces.

---

## 9. Integration & Architectural Documentation

Detailed companion documentation is available in [`docs/`](docs/):
- [Architecture Specification](docs/ARCHITECTURE.md): Component interactions, trust boundaries, and authorization algorithms.
- [Integration Guide](docs/INTEGRATION_GUIDE.md): How external Node.js, Express, and React applications consume `@modular-auth/core` and `@modular-auth/api`.
- [Security Model & Threat Boundaries](docs/SECURITY_MODEL.md): Threat vectors, mitigations, and defense-in-depth guarantees.
- [Administrative Account Provisioning](docs/ADMIN_PROVISIONING.md): Step-by-step superadmin bootstrap procedure.
- [Database Security Review](docs/SECURITY_REVIEW_DATABASE.md): PostgreSQL triggers, RLS policies, and advisory locking audit.

---

## 10. Official Plugin & Modular Distribution

Modular Auth Foundation is packaged as an official, reusable plugin for the ArchScale ecosystem:
- **`@modular-auth/core`**: Zero-dependency framework-agnostic TypeScript core library (RBAC, PBAC, permission matrix, domain error hierarchy).
- **`@modular-auth/api`**: Production-ready Express middleware plugin. Provides `createModularAuthPlugin` for one-line mounting into any Node.js/Express service, plus granular middleware exports (`authenticate`, `requirePlatformRole`, `requireOrgMembership`, `requirePermission`, `securityHeaders`, `corsMiddleware`, `createRateLimiter`).

```typescript
import express from 'express';
import { createModularAuthPlugin } from '@modular-auth/api';

const app = express();
app.use('/auth', createModularAuthPlugin({
  supabaseUrl: process.env.SUPABASE_URL!,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
}));
```

---

## 11. Current Status & Known Boundaries

- **Backend API & Plugin (`@modular-auth/api`)**: Production-ready, fully tested (102 automated tests passing across workspaces).
- **Core Library (`@modular-auth/core`)**: Zero dependencies outside zod, fully typed and tested.
- **Frontend Client (`apps/web`)**: Standalone backend foundation; ready for any React/Vite/Next.js client using standard Supabase Auth SDK.
- **Production Secret Configuration**: When deploying to staging or production, ensure `SUPABASE_SERVICE_ROLE_KEY` is populated in the server environment so that database queries can authenticate against PostgREST.

