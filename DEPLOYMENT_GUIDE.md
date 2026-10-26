# Production Deployment Guide: Render & Supabase

This guide provides technical instructions for deploying the **Modular Auth Foundation** Express API service to **Render** and connecting it securely to your **Supabase PostgreSQL** database.

---

## 1. Architecture Overview on Render

Modular Auth Foundation is structured as a TypeScript npm monorepo containing:
- `@modular-auth/core`: Framework-agnostic authentication and authorization contracts, RBAC/PBAC engine, and domain error hierarchy.
- `@modular-auth/api`: Secure Express.js backend service offering token verification, platform/org authorization middleware, and administrative role assignment endpoints.

When deployed to Render as a **Web Service**:
- Render executes the build process from the monorepo root.
- All TypeScript packages are compiled into JavaScript `dist/` folders.
- Render injects dynamic network configuration, notably `PORT`.
- The production server starts using Node.js directly from compiled JavaScript (`apps/api/dist/index.js`), completely independent of TypeScript runtime tools (`tsx` / `ts-node`).

---

## 2. Render Web Service Configuration

Create a new **Web Service** in the [Render Dashboard](https://dashboard.render.com/):

| Setting | Value | Description |
| :--- | :--- | :--- |
| **Name** | `modular-auth-api` | Service identifier |
| **Language / Environment** | `Node` | Standard Node.js runtime |
| **Root Directory** | `.` | Repository root (leave empty or enter `.`) |
| **Branch** | `main` | Production deployment branch |
| **Build Command** | `npm install && npm run build` | Installs monorepo dependencies and compiles all packages to `dist/` |
| **Start Command** | `npm start` | Executes `node dist/index.js` in the `@modular-auth/api` package |
| **Health Check Path** | `/health` | Render zero-downtime health probe endpoint |
| **Auto-Deploy** | `Yes` | Trigger builds automatically on push to `main` |

---

## 3. Required Environment Variables

Configure the following environment variables in the Render Dashboard under **Environment**:

| Variable Name | Required | Default / Example | Purpose |
| :--- | :---: | :--- | :--- |
| `NODE_ENV` | **Yes** | `production` | Enforces production security optimizations and validation rules |
| `PORT` | Auto | *Supplied by Render* | Automatically injected by Render (e.g. `10000`); API dynamically binds to this port |
| `SUPABASE_URL` | **Yes** | `https://vsllykwuqqmbitxvpuod.supabase.co` | Supabase project endpoint |
| `SUPABASE_SERVICE_ROLE_KEY` | **Yes** | `eyJhbGciOi...` | Supabase backend service-role secret (bypasses RLS for authoritative DB role lookups) |
| `SUPABASE_JWT_SECRET` | Optional | `your_supabase_jwt_secret` | Only required if your Supabase project uses symmetric `HS256` token signing |
| `CORS_ORIGIN` | **Yes** | `https://app.archscale.com` | Comma-separated allowlist of trusted frontend origins |
| `RATE_LIMIT_WINDOW_MS` | No | `900000` | Rate limit window in milliseconds (default: 15 minutes) |
| `RATE_LIMIT_MAX_REQUESTS` | No | `100` | Max global API requests per IP per window |
| `AUTH_RATE_LIMIT_MAX_REQUESTS`| No | `10` | Max sensitive auth attempts per IP per window |

> [!CAUTION]
> **Confidential Credential**: `SUPABASE_SERVICE_ROLE_KEY` has full administrative database privileges.
> - Never commit it to git.
> - Never expose it in client-side code, Vite builds, or React applications.
> - Set it exclusively in the Render Environment Secrets manager.

---

## 4. Supabase Database Preparation

Before starting the API in production, ensure your Supabase database schema, triggers, and initial administrative account are configured.

### Step 1: Run the Database Schema
1. Open the **Supabase Dashboard &rarr; SQL Editor**.
2. Open [`docs/DATABASE_SCHEMA.sql`](docs/DATABASE_SCHEMA.sql).
3. Execute the script to create:
   - `public.users`
   - `public.organizations` & `public.organization_memberships`
   - `public.projects`
   - `public.audit_logs`
   - Triggers: `handle_new_auth_user()` and `protect_platform_role_escalation()`
   - RLS security policies on all tables.

### Step 2: Bootstrap the Initial Superadmin
1. Sign up the initial superadmin user in Supabase Auth (e.g., `superadmin.modularauth@gmail.com`).
2. Note the user's UUID (e.g., `d6d1bbef-e141-4138-ac74-987070d05527`).
3. Run the atomic, concurrency-safe bootstrap function in the SQL Editor:
   ```sql
   SELECT public.bootstrap_initial_superadmin('d6d1bbef-e141-4138-ac74-987070d05527'::UUID);
   ```
4. Verify the user now has `platform_role = 'superadmin'` in `public.users`:
   ```sql
   SELECT id, email, platform_role FROM public.users WHERE id = 'd6d1bbef-e141-4138-ac74-987070d05527';
   ```

---

## 5. Production Security Architecture

1. **Fail-Closed Authorization**:
   - If `SUPABASE_SERVICE_ROLE_KEY` is missing in production, the API refuses to guess roles or fall back to client claims. It throws a `ConfigurationError` and fails closed.
   - If an unauthenticated user or an unauthorized role accesses a platform route, the API immediately returns `401 UNAUTHENTICATED` or `403 FORBIDDEN`.
2. **Asymmetric JWT Verification**:
   - The token verifier dynamically resolves signing keys from Supabase's `/.well-known/jwks.json` endpoint using `jose`.
   - Validates algorithm (ES256/RS256/HS256), signature, token expiry (`exp`), issuer (`iss`), and audience (`aud = 'authenticated'`).
3. **Helmet Security Headers**:
   - Automatically injects `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
4. **Strict CORS**:
   - Only origins explicitly defined in `CORS_ORIGIN` are permitted to make cross-origin requests.
5. **Rate Limiting**:
   - Global requests are throttled to prevent DoS.
   - Sensitive auth and credential routes are strictly throttled.
6. **Graceful Shutdown**:
   - Listens for `SIGTERM` and `SIGINT` signals emitted by Render during deploys or scaling.
   - Ceases accepting new connections, allows in-flight requests to complete, and cleanly exits within 10 seconds.

---

## 6. How to Verify the Deployed API

Replace `https://modular-auth-api.onrender.com` with your actual Render service URL:

### 1. Public Health Check
```bash
curl -i https://modular-auth-api.onrender.com/health
```
**Expected Response (`200 OK`)**:
```json
{
  "status": "ok",
  "timestamp": "2026-10-26T17:20:00.000Z"
}
```

### 2. Inspect Authenticated Identity
```bash
curl -i https://modular-auth-api.onrender.com/api/v1/auth/me \
  -H "Authorization: Bearer <SUPERADMIN_ACCESS_TOKEN>"
```
**Expected Response (`200 OK`)**:
```json
{
  "user": {
    "id": "d6d1bbef-e141-4138-ac74-987070d05527",
    "email": "superadmin.modularauth@gmail.com",
    "platformRole": "superadmin"
  }
}
```

### 3. Assign Platform Role to Another User
```bash
curl -i -X PATCH https://modular-auth-api.onrender.com/api/v1/platform/users/a800ea5c-667a-424a-aa09-49f6a4a8a222/role \
  -H "Authorization: Bearer <SUPERADMIN_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```
**Expected Response (`200 OK`)**:
```json
{
  "message": "Platform role updated successfully for user a800ea5c-667a-424a-aa09-49f6a4a8a222",
  "targetUserId": "a800ea5c-667a-424a-aa09-49f6a4a8a222",
  "newRole": "admin"
}
```

---

## 7. Troubleshooting Common Deployment Errors

### 1. `ConfigurationError: SUPABASE_SERVICE_ROLE_KEY is required in production environment`
- **Cause**: The application is running with `NODE_ENV=production` but `SUPABASE_SERVICE_ROLE_KEY` was not configured in Render's environment settings.
- **Resolution**: Open Render Dashboard &rarr; Service &rarr; **Environment**, add `SUPABASE_SERVICE_ROLE_KEY`, and trigger a redeploy.

### 2. `403 Forbidden: Platform access denied. Required role in [superadmin, founder], current role: 'none'`
- **Cause**: The authenticated user's record in `public.users` has `platform_role IS NULL` or the service-role key is invalid/unconfigured.
- **Resolution**:
  1. Confirm `SUPABASE_SERVICE_ROLE_KEY` is configured and matches the key from the Supabase Dashboard.
  2. Inspect the user in `public.users` via SQL:
     ```sql
     SELECT id, email, platform_role FROM public.users WHERE id = 'd6d1bbef-e141-4138-ac74-987070d05527';
     ```
  3. If `platform_role` is NULL, run the bootstrap procedure or assign it manually:
     ```sql
     UPDATE public.users SET platform_role = 'superadmin' WHERE id = 'd6d1bbef-e141-4138-ac74-987070d05527';
     ```

### 3. `401 Unauthorized: Invalid, expired, or revoked access token`
- **Cause**: The provided Bearer token has expired (default Supabase JWT lifetime is 3600 seconds), was issued for a different Supabase project, or the signature failed verification.
- **Resolution**: Request a fresh `access_token` from Supabase Auth (`/auth/v1/token?grant_type=password` or `/auth/v1/token?grant_type=refresh_token`) and verify that `SUPABASE_URL` matches your project.

### 4. `Port Binding / Health Check Timeout on Render`
- **Cause**: The server is hardcoded to listen on a static port or not listening on `0.0.0.0` / IPv6 dual-stack.
- **Resolution**: The codebase reads `process.env.PORT` dynamically and binds to `0.0.0.0` via Express's default `app.listen(port)`. Ensure the Health Check Path in Render is configured as `/health`.
