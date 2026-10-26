import { Request, Response, NextFunction, RequestHandler } from 'express';
import { z, ZodError } from 'zod';

export interface RequestValidationSchemas {
  readonly body?: z.ZodTypeAny;
  readonly params?: z.ZodTypeAny;
  readonly query?: z.ZodTypeAny;
}

/**
 * Middleware that validates incoming request parameters, query, and body using Zod.
 * Rejects invalid requests with HTTP 400 and structured validation details.
 */
export function validateRequest(schemas: RequestValidationSchemas): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (schemas.params) {
        const parsedParams = await schemas.params.parseAsync(req.params);
        req.params = parsedParams as Record<string, string>;
      }
      if (schemas.query) {
        const parsedQuery = await schemas.query.parseAsync(req.query);
        req.query = parsedQuery as Record<string, any>;
      }
      if (schemas.body) {
        req.body = await schemas.body.parseAsync(req.body);
      }
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        res.status(400).json({
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid request input',
            details: error.issues.map((issue) => ({
              field: issue.path.join('.'),
              message: issue.message,
            })),
          },
        });
        return;
      }
      next(error);
    }
  };
}
