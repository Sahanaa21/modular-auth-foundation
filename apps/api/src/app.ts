import express, { Express } from 'express';
import { z } from 'zod';
import {
  ITokenVerifier,
  IAuthorizationEngine,
  IOrganizationService,
  IAuditLogger,
  StandardPermissions,
  PlatformRoles,
} from '@modular-auth/core';
import { securityHeaders } from './middleware/security-headers.js';
import { corsMiddleware } from './middleware/cors.js';
import { createRateLimiter } from './middleware/rate-limiter.js';
import { authenticate } from './middleware/authenticate.js';
import { requirePlatformRole } from './middleware/require-role.js';
import { requireOrgMembership } from './middleware/require-org-membership.js';
import { requirePermission } from './middleware/require-permission.js';
import { validateRequest } from './middleware/validate-request.js';
import { errorHandler } from './middleware/error-handler.js';

export interface AppDependencies {
  readonly tokenVerifier: ITokenVerifier;
  readonly authzEngine: IAuthorizationEngine;
  readonly orgService: IOrganizationService;
  readonly auditLogger: IAuditLogger;
  readonly corsOrigin?: string;
  readonly rateLimitWindowMs?: number;
  readonly rateLimitMax?: number;
  readonly authRateLimitMax?: number;
}

/**
 * Creates and configures the Express application with all security middleware and routes.
 */
export function createApp(dependencies: AppDependencies): Express {
  const app = express();

  // 1. Security Headers & Strict CORS
  app.use(securityHeaders());
  app.use(
    corsMiddleware({
      allowedOrigins: dependencies.corsOrigin ? dependencies.corsOrigin.split(',') : ['http://localhost:5173'],
    })
  );

  // 2. Body Parser (bounded payload size)
  app.use(express.json({ limit: '100kb' }));

  // 3. Global Rate Limiter
  const globalLimiter = createRateLimiter({
    windowMs: dependencies.rateLimitWindowMs ?? 15 * 60 * 1000,
    max: dependencies.rateLimitMax ?? 100,
  });
  app.use(globalLimiter);

  // 4. Sensitive Auth Route Rate Limiter (e.g. 5 or 10 requests per window)
  const authLimiter = createRateLimiter({
    windowMs: dependencies.rateLimitWindowMs ?? 15 * 60 * 1000,
    max: dependencies.authRateLimitMax ?? 10,
    message: 'Too many authentication attempts. Please try again later.',
  });

  // ==========================================
  // Public Routes
  // ==========================================
  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Sensitive auth demo route (demonstrating strict rate-limiting)
  app.post(
    '/api/v1/auth/login-attempt',
    authLimiter,
    validateRequest({
      body: z.object({
        email: z.string().email('Invalid email address'),
        password: z.string().min(8, 'Password must be at least 8 characters'),
      }),
    }),
    (_req, res) => {
      res.status(200).json({ message: 'Auth payload received' });
    }
  );

  // Common authenticated middleware instance
  const authMiddleware = authenticate({
    tokenVerifier: dependencies.tokenVerifier,
  });

  const tenantMiddleware = requireOrgMembership({
    orgService: dependencies.orgService,
  });

  // ==========================================
  // Authenticated Context Inspection Route
  // ==========================================
  app.get('/api/v1/auth/me', authMiddleware, (req, res) => {
    res.status(200).json({
      user: req.auth?.user,
    });
  });

  // ==========================================
  // Platform-Scoped Administrative Routes
  // ==========================================
  app.get(
    '/api/v1/platform/metrics',
    authMiddleware,
    requirePlatformRole([PlatformRoles.FOUNDER, PlatformRoles.DEVELOPER, PlatformRoles.CLIENT_SERVICING, PlatformRoles.ACCOUNTS]),
    (req, res) => {
      res.status(200).json({
        scope: 'platform',
        userRole: req.auth?.user.platformRole,
        metrics: { uptimeSeconds: process.uptime(), activeSessions: 42 },
      });
    }
  );

  app.get(
    '/api/v1/platform/system-settings',
    authMiddleware,
    requirePlatformRole([PlatformRoles.FOUNDER]),
    (_req, res) => {
      res.status(200).json({
        scope: 'platform',
        maintenanceMode: false,
        version: '1.0.0',
      });
    }
  );

  // ==========================================
  // Tenant-Scoped Organization Routes
  // ==========================================
  // 1. List Projects (Read permission required)
  app.get(
    '/api/v1/organizations/:orgId/projects',
    authMiddleware,
    tenantMiddleware,
    requirePermission({
      authzEngine: dependencies.authzEngine,
      action: StandardPermissions.RESOURCE_READ,
      resourceType: 'project',
      auditLogger: dependencies.auditLogger,
    }),
    (req, res) => {
      res.status(200).json({
        organizationId: req.tenant?.organizationId,
        membershipRole: req.tenant?.membership.role,
        projects: [
          { id: 'proj-1', name: 'Alpha Project', orgId: req.tenant?.organizationId },
          { id: 'proj-2', name: 'Beta Project', orgId: req.tenant?.organizationId },
        ],
      });
    }
  );

  // 2. Create Project (Create permission required)
  const createProjectSchema = z.object({
    name: z.string().min(1, 'Project name is required'),
    description: z.string().optional(),
  });

  app.post(
    '/api/v1/organizations/:orgId/projects',
    authMiddleware,
    tenantMiddleware,
    requirePermission({
      authzEngine: dependencies.authzEngine,
      action: StandardPermissions.RESOURCE_CREATE,
      resourceType: 'project',
      auditLogger: dependencies.auditLogger,
    }),
    validateRequest({ body: createProjectSchema }),
    (req, res) => {
      res.status(201).json({
        message: 'Project created successfully',
        project: {
          id: 'proj-new-123',
          name: req.body.name,
          organizationId: req.tenant?.organizationId,
        },
      });
    }
  );

  // 3. Delete Project (Delete permission required + resource parameter)
  app.delete(
    '/api/v1/organizations/:orgId/projects/:projectId',
    authMiddleware,
    tenantMiddleware,
    requirePermission({
      authzEngine: dependencies.authzEngine,
      action: StandardPermissions.RESOURCE_DELETE,
      resourceType: 'project',
      resourceIdParam: 'projectId',
      auditLogger: dependencies.auditLogger,
    }),
    (req, res) => {
      res.status(200).json({
        message: `Project ${req.params.projectId} deleted successfully`,
        organizationId: req.tenant?.organizationId,
      });
    }
  );

  // 4. Invite Member (Member invite permission required)
  const inviteMemberSchema = z.object({
    email: z.string().email('Valid email is required'),
    role: z.enum(['business_owner', 'leader', 'manager', 'executive', 'intern', 'collaborator', 'guest']),
  });

  app.post(
    '/api/v1/organizations/:orgId/members',
    authMiddleware,
    tenantMiddleware,
    requirePermission({
      authzEngine: dependencies.authzEngine,
      action: StandardPermissions.MEMBER_INVITE,
      resourceType: 'member',
      auditLogger: dependencies.auditLogger,
    }),
    validateRequest({ body: inviteMemberSchema }),
    (req, res) => {
      res.status(201).json({
        message: `Invitation sent to ${req.body.email}`,
        organizationId: req.tenant?.organizationId,
      });
    }
  );

  // 5. Centralized Fail-Closed Error Handler
  app.use(errorHandler());

  return app;
}
