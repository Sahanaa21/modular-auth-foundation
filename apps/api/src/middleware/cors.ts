import cors from 'cors';
import { RequestHandler } from 'express';

export interface CorsOptions {
  readonly allowedOrigins: string[];
}

/**
 * Creates strict CORS middleware allowing only whitelisted origins and safe headers.
 */
export function corsMiddleware(options: CorsOptions): RequestHandler {
  return cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl, or same-origin server-to-server)
      if (!origin) {
        return callback(null, true);
      }

      if (options.allowedOrigins.includes(origin) || options.allowedOrigins.includes('*')) {
        return callback(null, true);
      }

      return callback(new Error(`Origin '${origin}' is not allowed by CORS policy`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Organization-Id'],
    exposedHeaders: ['RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset'],
    maxAge: 86400, // 24 hours preflight cache
  });
}
