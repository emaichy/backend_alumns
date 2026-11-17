import type { NextFunction, Request, Response } from "express";
import { forbidden, unauthorized } from "../errors/httpError";
import type { AuthService } from "../services/authService";

/**
 * Middleware que exige un JWT válido en el header
 * `Authorization: Bearer <token>`. Adjunta el payload a `req.auth`.
 */
export function requireAuth(authService: AuthService) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const header = req.header("authorization") ?? "";
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) {
      throw unauthorized("Falta el token de autenticación (Bearer)");
    }
    const payload = authService.verify(token);
    authService.getProfile(payload);
    req.auth = payload;
    next();
  };
}

export function requireRole(authService: AuthService, roleName: string) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.auth) throw unauthorized();
    if (authService.getProfile(req.auth).rol_nombre !== roleName) {
      throw forbidden(`Se requiere el rol ${roleName}`);
    }
    next();
  };
}

export function requireAnyRole(authService: AuthService, roleNames: string[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.auth) throw unauthorized();
    const roleName = authService.getProfile(req.auth).rol_nombre;
    if (!roleName || !roleNames.includes(roleName)) {
      throw forbidden(`Se requiere uno de estos roles: ${roleNames.join(", ")}`);
    }
    next();
  };
}
