# Modular Auth Foundation: Security Model & Threat Boundaries

This document formalizes the security architecture, threat model, trust boundaries, and mitigation strategies implemented in the **Modular Auth Foundation**.

---

## 1. Trust Boundaries

```
[ UNTRUSTED CLIENT ] 
         │ (HTTPS / Bearer JWT)
         ▼
[ BOUNDARY 1: API Gateway & Network Perimeter ]
  • Helmet Security Headers (CSP, HSTS, X-Frame-Options: DENY)
  • CORS Allowlist (Strict origin validation)
  • Global & Sensitive Auth Route Rate Limiting
         │
         ▼
[ BOUNDARY 2: Express Application Service (@modular-auth/api) ]
  • Asymmetric JWT Verification via Supabase JWKS (ES256/RS256)
  • Issuer (iss) & Audience (aud) Verification
  • Authoritative User Profile Hydration from public.users
  • Role-Based & Permission-Based Access Control (RBAC/PBAC)
  • Multi-Tenant Isolation & Membership Enforcement
  • Parameter & Body Schema Validation (Zod RFC 4122 UUIDs)
  • Zero-Secret-Leakage Error Handling & Audit Logging
         │
         ▼ (PostgREST / Service-Role Connection)
[ BOUNDARY 3: Supabase PostgreSQL Database ]
  • Row Level Security (RLS) Fail-Closed Policies
  • Security Definer Triggers (Anti-Escalation: protect_platform_role_escalation)
  • Immutable Audit Log Permissions (Revoked from public/anon/authenticated)
  • Concurrency-Safe Bootstrap Lock (pg_advisory_xact_lock)
```

---

## 2. Threat Analysis & Mitigations

### 2.1 Forged, Expired, or Manipulated Tokens
- **Threat**: Attackers forge JWTs with arbitrary claims or replay expired tokens.
- **Mitigation**:
  - The API uses `jose.createRemoteJWKSet` pointing to the authoritative Supabase JWKS endpoint (`https://<project>.supabase.co/auth/v1/.well-known/jwks.json`).
  - Supported signing algorithms (`ES256`, `RS256`, `HS256`) are verified against cryptographically checked signatures.
  - Expiration (`exp`) is enforced with bounded clock tolerance (default: 10s).
  - Issuer (`iss`) must strictly match `https://<project>.supabase.co/auth/v1`.
  - Audience (`aud`) must include `'authenticated'`.

### 2.2 Client-Side Role Spoofing (JWT Metadata Poisoning)
- **Threat**: In Supabase Auth, users can update their own `raw_user_meta_data`. If an application trusts `jwt.claims.user_metadata.role`, a user can make themselves an administrator.
- **Mitigation**:
  - **Zero Trust in Token Role Claims**: The foundation never reads platform roles from the JWT.
  - After token validation, the user's UUID is extracted (`token.sub`), and their authoritative role is queried directly from `public.users.platform_role` via server-side connection.

### 2.3 Horizontal Privilege Escalation & Cross-Tenant Data Leakage (IDOR)
- **Threat**: A user belonging to Organization A manipulates request IDs to view or mutate Organization B's data.
- **Mitigation**:
  - `requireOrgMembership` middleware extracts the target tenant identifier and queries `public.organization_memberships`.
  - If no active membership exists for the authenticated user in that tenant, the request is immediately rejected (`403 Forbidden`).
  - PostgreSQL Row Level Security enforces tenant isolation at the database layer as defense-in-depth.

### 2.4 Vertical Privilege Escalation & Unauthorized Self-Promotion
- **Threat**: An ordinary user or tenant admin calls `PATCH /api/v1/platform/users/:id/role` or executes direct SQL to elevate themselves to `superadmin`.
- **Mitigation**:
  - **API Layer**: `requireRole(['superadmin', 'founder'])` blocks any caller without authoritative platform privileges.
  - **Self-Lockout Prevention**: The API explicitly forbids a Superadmin from modifying their own platform role to prevent accidental system lockout.
  - **Database Layer**:
    - `REVOKE UPDATE (platform_role) ON public.users FROM authenticated, anon;`
    - Trigger `trg_protect_platform_role` intercepts all `UPDATE` queries on `public.users.platform_role`. Unless executed by a trusted backend role or an authenticated user with `superadmin`/`founder`, the database aborts the transaction with an exception.

### 2.5 Bootstrap Race Conditions & Multiple Superadmins
- **Threat**: When initializing a new project where zero superadmins exist, multiple actors attempt simultaneous promotions.
- **Mitigation**:
  - `public.bootstrap_initial_superadmin(UUID)` acquires an exclusive transaction advisory lock:
    `PERFORM pg_advisory_xact_lock(hashtext('bootstrap_initial_superadmin_lock'));`
  - It validates that `COUNT(superadmin) = 0`.
  - Once the first superadmin commits, all subsequent calls are permanently rejected by the lock condition.

### 2.6 Credential Leakage & Log Poisoning
- **Threat**: API keys, service role secrets, or user access tokens are printed in server logs or leaked in error responses.
- **Mitigation**:
  - `apps/api/src/config/env.ts` strips secrets from logging.
  - `apps/api/src/services/audit-logger.ts` explicitly strips tokens, passwords, and sensitive headers.
  - `apps/api/src/middleware/error-handler.ts` sanitizes all client error responses. Stack traces and database internal errors are hidden in production and non-development environments.

---

## 3. Security Invariants

1. **Fail-Closed Default**: Any missing configuration, missing user profile, invalid token, or database query failure results in immediate denial (`401` or `403` or `500` safe response).
2. **Authoritative State in Database**: Neither user input, HTTP headers, nor client-editable JWT fields dictate authorization.
3. **Defense-in-Depth**: Authorization rules exist in application middleware *and* in PostgreSQL schema constraints and triggers.
