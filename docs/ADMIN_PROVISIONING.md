# Administrative Account Provisioning Guide

## Overview

This guide details the procedure for provisioning platform administrators in the **Modular Auth Foundation** without compromising security, leaking secrets, or using insecure email-based authorization checks.

### Target Administrative Accounts
- `superadmin.modularauth@gmail.com` &rarr; Target Platform Role: **`superadmin`**
- `admin.modularauth@gmail.com` &rarr; Target Platform Role: **`admin`**

---

## 1. Security Architecture & Threat Model

### Invariant: Never Authorize by Email Address
Authorization rules must **never** check `if (user.email === 'admin@domain.com')`:
- Email strings can be manipulated in case-sensitivity edge cases, modified before verification, or spoofed in unverified identity states.
- Identity in Supabase Auth is pinned to the immutable **Supabase User UUID** (`auth.users.id`).
- Authorization is strictly resolved from the verified `public.users.platform_role` column in the database matching that UUID.

### Defense-in-Depth Protections
1. **Database CHECK Constraint**: Platform roles are validated against `('superadmin', 'admin', 'founder', 'developer', 'client_servicing', 'accounts')`.
2. **Column Privilege Revocation**: The `platform_role` column cannot be updated by public `authenticated` or `anon` roles via PostgREST/Supabase client.
3. **Escalation Prevention Trigger**: The PostgreSQL trigger `trg_protect_platform_role` prevents non-superadmins from altering their own or other users' platform roles.
4. **Concurrency-Safe One-Time Bootstrap**: `public.bootstrap_initial_superadmin(UUID)` acquires an advisory transaction lock (`pg_advisory_xact_lock`) and verifies that zero superadmins exist before promoting the initial superadmin. It permanently locks itself once executed.
5. **Fail-Closed Evaluator**: Any unknown role, missing record, or null role defaults to `null` and access is denied (HTTP 403/401).

---

## 2. Safe Provisioning Procedure

Follow these manual steps to provision the administrative accounts:

### Step 1: Apply the Bootstrap Migration in Supabase SQL Editor
Run the migration file [`docs/migrations/001_bootstrap_initial_superadmin.sql`](file:///c:/Users/sahan/OneDrive/Desktop/ArchScale/modular-auth-foundation/docs/migrations/001_bootstrap_initial_superadmin.sql) in the Supabase SQL Editor. This:
- Updates the trigger `protect_platform_role_escalation` to recognize trusted database administrator roles (`postgres`, `supabase_admin`, `service_role`).
- Deploys the atomic, concurrency-safe `public.bootstrap_initial_superadmin(UUID)` function.
- Hardens audit log write permissions.

### Step 2: Retrieve the Superadmin Supabase UUID
In the **Supabase SQL Editor**:

```sql
SELECT id, email, created_at, email_confirmed_at 
FROM auth.users 
WHERE email = 'superadmin.modularauth@gmail.com';
```

Copy the returned UUID (e.g., `0192e21b-6cb7-7000-84a1-000000000001`).

### Step 3: Execute the Initial Superadmin Bootstrap
In the **Supabase SQL Editor** (running under database administrator role `postgres`):

```sql
SELECT public.bootstrap_initial_superadmin('<SUPERADMIN_UUID>');
```

Expected output:
```json
{
  "status": "SUCCESS",
  "message": "Initial Super Administrator successfully provisioned",
  "userId": "<SUPERADMIN_UUID>",
  "email": "superadmin.modularauth@gmail.com",
  "role": "superadmin"
}
```

#### Verification of Permanent Bootstrap Lock:
If you attempt to call `bootstrap_initial_superadmin` again:
```sql
SELECT public.bootstrap_initial_superadmin('<ANY_UUID>');
```
PostgreSQL will reject it with:
```text
ERROR: Bootstrap locked: A Super Administrator or Founder already exists. Subsequent role assignments must be performed by an authenticated Super Administrator through the API.
```

### Step 4: Retrieve the Admin Supabase UUID
In the **Supabase SQL Editor**:

```sql
SELECT id, email, created_at, email_confirmed_at 
FROM auth.users 
WHERE email = 'admin.modularauth@gmail.com';
```

Copy the returned UUID for `admin.modularauth@gmail.com`.

### Step 5: Assign the `admin` Role via Authenticated API
Now that the initial Superadmin is bootstrapped, all subsequent platform role assignments are performed via the backend API with full audit logging:

1. Log in as `superadmin.modularauth@gmail.com` using Supabase Auth to obtain an access token.
2. Issue an authenticated `PATCH` request to the API:

```http
PATCH /api/v1/platform/users/<ADMIN_UUID>/role
Host: localhost:4000
Authorization: Bearer <SUPERADMIN_ACCESS_TOKEN>
Content-Type: application/json

{
  "role": "admin"
}
```

Expected response (`200 OK`):
```json
{
  "message": "Platform role updated successfully for user <ADMIN_UUID>",
  "targetUserId": "<ADMIN_UUID>",
  "newRole": "admin"
}
```

---

## 3. Runtime Verification of Capabilities

Once provisioned:

| User | Platform Role | Platform Metrics (`/api/v1/platform/metrics`) | System Settings (`/api/v1/platform/system-settings`) | Role Assignment (`PATCH /api/v1/platform/users/:id/role`) |
| :--- | :--- | :--- | :--- | :--- |
| `superadmin.modularauth@gmail.com` | `superadmin` | `200 OK` | `200 OK` | `200 OK` |
| `admin.modularauth@gmail.com` | `admin` | `200 OK` | `403 Forbidden` | `403 Forbidden` |
| Ordinary User | `null` | `403 Forbidden` | `403 Forbidden` | `403 Forbidden` |
