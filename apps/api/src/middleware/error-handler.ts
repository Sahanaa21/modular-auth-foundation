import { Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import { AuthBaseError } from '@modular-auth/core';

/**
 * Centralized fail-closed error handling middleware.
 * Prevents leaking internal stack traces, database schemas, or secrets to clients.
 */
export function errorHandler(): ErrorRequestHandler {
  return (err: unknown, _req: Request, res: Response, _next: NextFunction): void => {
    // Known domain errors from @modular-auth/core
    if (err instanceof AuthBaseError) {
      res.status(err.statusCode).json(err.toJSON());
      return;
    }

    const error = err as Error;

    // CORS policy violations
    if (error.message && error.message.includes('CORS policy')) {
      res.status(403).json({
        error: {
          code: 'CORS_ORIGIN_DENIED',
          message: error.message,
        },
      });
      return;
    }

    // JSON parsing errors
    if ('type' in error && error.type === 'entity.parse.failed') {
      res.status(400).json({
        error: {
          code: 'MALFORMED_JSON',
          message: 'Malformed request JSON payload',
        },
      });
      return;
    }

    // Log the internal error safely on the server side
    console.error('Unhandled internal server error:', {
      name: error.name,
      message: error.message,
    });

    // Return a generic, sanitized 500 error to the client
    res.status(500).json({
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected internal server error occurred',
      },
    });
  };
}
