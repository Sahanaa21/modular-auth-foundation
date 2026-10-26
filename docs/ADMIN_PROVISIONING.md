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
4. **Fail-Closed Evaluator**: Any unknown role, missing record, or null role defaults to `null` and access is denied (HTTP 403/401).

---

## 2. Safe Provisioning Procedure

Follow these manual steps to provision the administrative accounts:

### Step 1: Create Identities in Supabase Auth
You can create the user identities using either the Supabase Studio Dashboard or the Supabase CLI.

#### Via Supabase Studio Dashboard:
1. Navigate to **Authentication &rarr; Users**.
2. Click **Add user** &rarr; **Send invitation** (or **Create user** with a strong, temporary password).
3. Enter `superadmin.modularauth@gmail.com`.
4. Repeat for `admin.modularauth@gmail.com`.
5. Ensure both accounts complete email verification and set up Multi-Factor Authentication (MFA).

### Step 2: Retrieve the Immutable Supabase User UUIDs
In the Supabase Studio Dashboard (**Authentication &rarr; Users**) or via SQL query in the Supabase SQL Editor:

```sql
SELECT id, email, created_at, email_confirmed_at 
FROM auth.users 
WHERE email IN (
    'superadmin.modularauth@gmail.com',
    'admin.modularauth@gmail.com'
);
```

You will receive the unique UUID for each account (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`).

### Step 3: Assign the Platform Roles in `public.users`
In the **Supabase SQL Editor** (running with Postgres superuser privileges):

```sql
-- 1. Assign Super Administrator role
UPDATE public.users
SET platform_role = 'superadmin'
WHERE id = '<SUPERADMIN_AUTH_USER_UUID>';

-- 2. Assign Administrator role
UPDATE public.users
SET platform_role = 'admin'
WHERE id = '<ADMIN_AUTH_USER_UUID>';
```

> **Note**: The automated trigger `on_auth_user_created` (defined in `docs/DATABASE_SCHEMA.sql`) automatically creates a row in `public.users` when each user registers in `auth.users`, initialized with `platform_role = NULL`. The queries above assign the explicit administrative privileges.

### Step 4: Verify Role Assignments
Verify the assignments directly:

```sql
SELECT id, email, platform_role, created_at 
FROM public.users 
WHERE email IN (
    'superadmin.modularauth@gmail.com',
    'admin.modularauth@gmail.com'
);
```

Expected output:
| email | platform_role |
| :--- | :--- |
| `superadmin.modularauth@gmail.com` | `superadmin` |
| `admin.modularauth@gmail.com` | `admin` |

---

## 3. Runtime Verification via API

Once assigned, the API evaluates permissions upon every authenticated request:

1. **Superadmin Capabilities** (`superadmin`):
   - Access to `/api/v1/platform/metrics` &rarr; `200 OK`
   - Access to `/api/v1/platform/system-settings` &rarr; `200 OK`
   - Granted permissions: `platform:manage_all`, `platform:manage_users`, `platform:view_system`, `platform:billing_audit`, `audit_log:view`.
2. **Admin Capabilities** (`admin`):
   - Access to `/api/v1/platform/metrics` &rarr; `200 OK`
   - Access to `/api/v1/platform/system-settings` &rarr; `403 Forbidden` (only Superadmin/Founder has access)
   - Granted permissions: `platform:manage_users`, `platform:view_system`, `platform:view_metrics`, `platform:support_access`, `audit_log:view`.
3. **Ordinary Users** (`platform_role = NULL`):
   - Access to any platform route &rarr; `403 Forbidden`.
