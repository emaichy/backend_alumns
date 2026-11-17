import type { Request, Response } from "express";
import { asyncHandler } from "../middleware/asyncHandler";
import { parseBody } from "../middleware/validate";
import {
  credentialsSchema,
  profileUpdateSchema,
  refreshTokenSchema,
  registrationSchema,
  usuarioRegistrationSchema,
} from "../schemas/schemas";
import type { AuthService } from "../services/authService";

export function createAuthController(authService: AuthService) {
  const register = asyncHandler(async (req: Request, res: Response) => {
    if (
      typeof req.body === "object" &&
      req.body !== null &&
      ("apellido_paterno" in req.body || "rol_id" in req.body)
    ) {
      const data = parseBody(usuarioRegistrationSchema, req.body);
      const user = await authService.registerUsuario(data);
      res.status(201).json({ user });
      return;
    }

    const { email, password, nombre, apellido, matricula } = parseBody(
      registrationSchema,
      req.body,
    );
    const user = await authService.register(email, password, {
      nombre,
      apellido,
      matricula,
    });
    res.status(201).json({ user });
  });

  const login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = parseBody(credentialsSchema, req.body);
    const result = await authService.login(email, password);
    res.status(200).json(result);
  });

  const refresh = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = parseBody(refreshTokenSchema, req.body);
    const result = await authService.refresh(refreshToken);
    res.status(200).json(result);
  });

  const logout = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.body;
    // req.auth lo garantiza requireAuth
    authService.logout(req.auth!, refreshToken);
    res.status(200).json({ message: "Sesión cerrada" });
  });

  const me = asyncHandler(async (req: Request, res: Response) => {
    const payload = req.auth!;
    const user = authService.getProfile(payload);
    res.json({ data: user, user, claims: payload });
  });

  const updateMe = asyncHandler(async (req: Request, res: Response) => {
    const payload = req.auth!;
    const data = parseBody(profileUpdateSchema, req.body);
    const user = authService.updateProfile(payload, data);
    res.json({ data: user, user });
  });

  return { register, login, refresh, logout, me, updateMe };
}