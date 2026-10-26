# Modular Auth Foundation

A modular, enterprise-grade authentication and authorization foundation for React and Node.js applications.

## Overview

Modular Auth Foundation provides a reusable architecture for web applications requiring:
- **Authentication**: Supabase Auth integration (Email/Password, Email Verification, Password Reset, Token Refresh).
- **Session Handling**: Secure access-token verification and session lifecycle management.
- **Dual-Tier Authorization**: Separate **Platform-level roles** (`founder`, `developer`, `client_servicing`, `accounts`) and **Organization-level roles** (`business_owner`, `leader`, `manager`, `executive`, `intern`, `collaborator`, `guest`).
- **Organization Isolation**: Multi-tenant workspace enforcement and IDOR defense.
- **Protected API Middleware**: Express.js middleware for authentication, authorization, rate limiting, and security headers.
- **Audit Logging**: Security-focused event logging for compliance and monitoring.

---

## Architecture & Monorepo Structure

```
modular-auth-foundation/
├── apps/
│   ├── api/                  # Node.js + Express backend service
│   └── web/                  # React + Vite demonstration web application
├── packages/
│   └── auth-core/            # Reusable framework-agnostic auth & authz library
│       └── src/types/        # Core TypeScript interface contracts
├── docs/
│   ├── ARCHITECTURE.md       # Full architecture specification & trust boundaries
│   └── IMPLEMENTATION_PLAN.md# Phased milestone breakdown & test gates
├── tests/                    # Automated unit, integration, and E2E test suites
└── .gitignore                # Production security-first git ignore rules
```

---

## Core Interfaces

All core interfaces are defined in `packages/auth-core/src/types/`:
- **`IAuthProvider`**: Abstract authentication provider operations (sign up, sign in, sign out, password recovery).
- **`ITokenVerifier`**: Abstract token verification contract for backend middleware.
- **`IAuthorizationEngine`**: Multi-dimensional role and resource-level permission evaluation.
- **`IOrganizationService`**: Multi-tenant membership lookup and tenant validation.
- **`IAuditLogger`**: Structured security audit event emission.

---

## Phased Implementation Roadmap

1. **Milestone 1**: Monorepo Foundation & Core Package (`packages/auth-core`)
2. **Milestone 2**: Backend API Architecture & Security Middleware (`apps/api`)
3. **Milestone 3**: Authorization Data Store & Tenant Isolation Services
4. **Milestone 4**: Frontend Demonstration Application (`apps/web`)
5. **Milestone 5**: Automated Test Suite & CI/CD Pipeline
6. **Milestone 6**: Integration Documentation & Deployment Guides

For detailed specifications, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md).
