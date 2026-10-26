# Modular Auth Foundation: Architecture Specification

## 1. Executive Summary

**Modular Auth Foundation** provides a reusable, enterprise-grade authentication and authorization foundation for React and Node.js applications. It decouples identity authentication (delegated to Supabase Auth) from application-level multi-tenant authorization, role-based access control (RBAC), and protected API middleware.

### Core Objectives
1. **Reusability**: Decoupled core package (`packages/auth-core`) that consumer applications can integrate into any Node.js/Express backend or React frontend.
2. **Strict Multi-Tenancy**: Complete isolation between organizations. Preventing Insecure Direct Object References (IDOR) and cross-tenant data leakage.
3. **Dual-Tier Role Separation**: Rigorous distinction between **Platform-level roles** (system operators) and **Organization-level roles** (tenant members). A user with an organization role never gains platform-level administrative capabilities.
4. **Security-First Architecture**: Token verification on backend, fail-closed access evaluations, zero-secret-leakage logging, rate-limiting, and auditable security events.

---

## 2. High-Level Architecture & Logical Components

```
+-----------------------------------------------------------------------------------+
|                                 TRUST BOUNDARY 1                                  |
|  UNTRUSTED CLIENT ENVIRONMENT (Web / Mobile / React Consumer Application)         |
|                                                                                   |
|   +-----------------------+     +------------------------+                        |
|   |   Supabase Auth SDK   |     |    Auth State Provider |                        |
|   |  (Login/Signup/Reset) |     |   (Context & Hooks)    |                        |
|   +-----------+-----------+     +------------+-----------+                        |
|               |                              |                                    |
+---------------|------------------------------|------------------------------------+
                | Auth Tokens                  | HTTP Requests + Bearer Token
                v                              v
+---------------+-----------+     +-------------------------------------------------+
|  SUPABASE MANAGED SERVICE |     |                TRUST BOUNDARY 2                 |
|  Identity Provider (IdP)  |     |  BACKEND API SERVICE (Node.js/Express: apps/api)|
|                           |     |                                                 |
|  - auth.users table       |     |  +-------------------------------------------+  |
|  - JWT issuance / refresh |     |  | 1. Security Headers (Helmet) & CORS       |  |
|  - Password reset emails  |     |  +-------------------------------------------+  |
+---------------------------+     |  | 2. Rate Limiting (Sensitive Auth Routes)  |  |
                                  |  +-------------------------------------------+  |
                                  |  | 3. Token Verification (ITokenVerifier)    |  |
                                  |  +-------------------------------------------+  |
                                  |  | 4. Identity & Tenancy Context Hydration   |  |
                                  |  +-------------------------------------------+  |
                                  |  | 5. Authorization Engine (RBAC / PBAC)     |  |
                                  |  +-------------------------------------------+  |
                                  |  | 6. Request Input Validation (Zod)         |  |
                                  |  +-------------------------------------------+  |
                                  |  | 7. Security Audit Logger (IAuditLogger)   |  |
                                  |  +-------------------------------------------+  |
                                  |  | 8. Protected Route Handlers               |  |
                                  |  +-------------------------------------------+  |
                                  |  | 9. Fail-Closed Error Handler              |  |
                                  |  +-------------------------------------------+  |
                                  +-----------------------+-------------------------+
                                                          | Parameterized Queries & RLS
                                                          v
                                  +-------------------------------------------------+
                                  |                 TRUST BOUNDARY 3                |
                                  |          SUPABASE POSTGRESQL DATABASE           |
                                  |                                                 |
                                  |  - users (id, email, platform_role)             |
                                  |  - organizations (id, name, slug, status)       |
                                  |  - organization_memberships (user_id, org_id)   |
                                  |  - audit_logs (actor, action, target, outcome)  |
                                  |  - Row Level Security (RLS) enforcement         |
                                  +-------------------------------------------------+
```

---

## 3. Trust Boundaries & Authentication Flow

### Trust Boundary 1: Client Application (Browser / Consumer App)
* **Threat Profile**: Untrusted. Client memory, local storage, and DOM can be inspected, manipulated, or intercepted by scripts or browser extensions.
* **Security Controls**:
  - Only uses `SUPABASE_ANON_KEY` (public, limited privileges).
  - The `SUPABASE_SERVICE_ROLE_KEY` is **NEVER** bundled or exposed to frontend code.
  - Client-side role/permission checks are strictly for UX (showing/hiding buttons). The client cannot authorize any action.
  - Sends the JWT access token in standard `Authorization: Bearer <token>` headers to backend endpoints.

### Trust Boundary 2: Backend API (`apps/api`)
* **Threat Profile**: Trusted execution environment running behind reverse proxies or load balancers.
* **Security Controls**:
  - Independent validation of every incoming Bearer token using `ITokenVerifier`.
  - Verifies signature, expiration (`exp`), issuer (`iss`), and audience (`aud`).
  - Does NOT trust user IDs, roles, or organization IDs supplied in request bodies or query params.
  - Queries database using parameterized queries and trusted server connections.
  - Sanitizes all outgoing errors to prevent leaking internal stack traces or database errors.

### Trust Boundary 3: Database & Identity Store (Supabase PostgreSQL)
* **Security Controls**:
  - Direct database access is restricted.
  - Tables use foreign key constraints, unique indexes, and audit timestamps.
  - Row Level Security (RLS) policies guard public access schemas if client-facing access is configured.

---

## 4. Role Hierarchy & Dual-Tier Authorization Model

### Separation of Concerns: Platform vs Organization
A common architectural vulnerability in multi-tenant SaaS is role collision (e.g. an organization `leader` gaining platform administrative routes because both roles share similar names or permission strings).

Modular Auth Foundation enforces strict dual-tier separation:

```
Platform Scope                                 Organization Scope (Tenant)
==============                                 ===========================
PlatformRoles:                                 OrgRoles:
  - founder                                      - business_owner
  - developer                                    - leader
  - client_servicing                             - manager
  - accounts                                     - executive
                                                 - intern
                                                 - collaborator
                                                 - guest
```

1. **Platform Privileges**: Evaluated solely against the user's `platform_role` record in the database.
2. **Organization Privileges**: Evaluated against the user's active `organization_memberships` record for the specific `organizationId`.
3. **No Cross-Pollution**: An organization role cannot fulfill a platform permission requirement, and a platform role does not bypass organization membership checks unless an audited platform break-glass action is explicitly defined.

### Authorization Decision Algorithm
Every protected operation invokes `IAuthorizationEngine.evaluate(platformRole, orgRole, request)`:
1. **Authentication Check**: Is identity present? If NO -> **Deny (401)**.
2. **Scope Evaluation**:
   - **Platform Action**: Check `platformRole` against `PlatformPermissionMatrix`. If matched -> **Allow**. Else -> **Deny (403)**.
   - **Organization Action**:
     - Extract target `organizationId` from validated parameters.
     - Fetch user's membership for `organizationId`. If none exists or status != `active` -> **Deny (403/404)**.
     - Check member's `orgRole` against `OrgPermissionMatrix`. If not matched -> **Deny (403)**.
     - **Resource-Level IDOR Verification**: Verify that the target resource (`resourceId`) belongs to `organizationId`. If not -> **Deny (404/403)**.
3. **Fail-Closed Guarantee**: Any unhandled condition or ambiguous role state defaults to **Deny**.

---

## 5. Middleware Architecture

The backend pipeline enforces security in sequential stages:

1. **`securityHeaders`**: Applies Helmet (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
2. **`corsHandler`**: Restricts allowed origins, methods, and credentials.
3. **`rateLimiter`**: Express rate limiting applied globally and with strict thresholds on auth endpoints.
4. **`authenticate`**:
   - Parses `Authorization: Bearer <token>`.
   - Calls `ITokenVerifier.verifyToken(token)`.
   - Hydrates `req.auth = { user, claims, token }`.
   - Returns `401 Unauthorized` on missing, expired, or invalid token.
5. **`requireOrgMembership({ orgIdParam })`**:
   - Extracts target tenant ID from request params/headers.
   - Validates user's membership in database.
   - Attaches `req.tenant = { organizationId, membership }`.
   - Returns `403 Forbidden` if membership is missing or suspended.
6. **`requirePermission(action, options)`**:
   - Calls `IAuthorizationEngine.evaluate(...)`.
   - Returns `403 Forbidden` if permission is not granted.
   - Emits `AUTHZ_ACCESS_DENIED` audit event on failure.
7. **`validateRequest(zodSchema)`**:
   - Validates `params`, `query`, and `body` with Zod.
   - Returns `400 Bad Request` with structured error details on schema mismatch.
8. **`errorHandler`**:
   - Centralized error handler.
   - Catches unhandled exceptions, logs security context, and returns sanitized JSON responses.

---

## 6. Audit Logging & Compliance

All security-sensitive operations generate structured audit events via `IAuditLogger`:
* Authentication success and failures (with client IP and User-Agent).
* Password reset requests and changes.
* Authorization denials (attempted permission, resource, actor).
* Organization membership changes (invitations, role updates, removals).
* Potential IDOR attempts (attempt to access resource belonging to another tenant).

**Zero Secret Leakage Rule**: Bearer tokens, passwords, API keys, and sensitive PII are strictly stripped before audit serialization.
