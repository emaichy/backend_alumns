import { Router } from "express";
import bcrypt from "bcryptjs";
import { config } from "../config/env";
import { asyncHandler } from "../middleware/asyncHandler";
import { requireAuth, requireRole } from "../middleware/auth";
import { badRequest, conflict, notFound } from "../errors/httpError";
import { parseBody } from "../middleware/validate";
import {
  usuarioActiveSchema,
  usuarioCreateSchema,
  usuarioUpdateSchema,
} from "../schemas/schemas";
import type { AuthService } from "../services/authService";
import type { RolRepository } from "../repositories/rolRepository";
import type {
  UsuarioConRol,
  UsuarioRepository,
  UpdateUsuarioData,
} from "../repositories/usuarioRepository";

function parseId(value: string): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id < 1) {
    throw badRequest("El id debe ser un entero positivo");
  }
  return id;
}

function toPublicUsuario(usuario: UsuarioConRol) {
  const { password_hash: _passwordHash, ...publicUsuario } = usuario;
  return publicUsuario;
}

export function createUsuarioRouter(
  usuarios: UsuarioRepository,
  roles: RolRepository,
  authService: AuthService,
): Router {
  const router = Router();
  const maestro = [
    requireAuth(authService),
    requireRole(authService, "maestro"),
  ];

  router.get(
    "/",
    ...maestro,
    (req, res) => {
      const { rol, search, activo } = req.query;
      let results: UsuarioConRol[];

      if (typeof search === "string" && search.trim()) {
        results = usuarios.search(search.trim());
      } else if (rol === "estudiante") {
        results = usuarios.findEstudiantes();
      } else if (rol === "maestro") {
        results = usuarios.findMaestros();
      } else if (activo === "true") {
        results = usuarios.findActivos();
      } else {
        results = usuarios.findAll();
      }

      res.json(results.map(toPublicUsuario));
    },
  );

  router.get(
    "/:id",
    ...maestro,
    (req, res) => {
      const usuario = usuarios.findById(parseId(req.params.id));
      if (!usuario) throw notFound("Usuario no encontrado");
      res.json(toPublicUsuario(usuario));
    },
  );

  router.post(
    "/",
    ...maestro,
    asyncHandler(async (req, res) => {
      const data = parseBody(usuarioCreateSchema, req.body);
      const user = await authService.createUsuario(data);
      res.status(201).json({ user });
    }),
  );

  router.put(
    "/:id",
    ...maestro,
    asyncHandler(async (req, res) => {
      const id = parseId(req.params.id);
      const current = usuarios.findById(id);
      if (!current) throw notFound("Usuario no encontrado");

      const data = parseBody(usuarioUpdateSchema, req.body);
      if (data.email) authService.assertUsuarioEmailAvailable(data.email, id);
      if (data.rol_id !== undefined && !roles.findById(data.rol_id)) {
        throw badRequest("El rol indicado no existe");
      }
      if (
        current.rol_nombre === "maestro" &&
        current.activo === 1 &&
        ((data.rol_id !== undefined && data.rol_id !== current.rol_id) ||
          data.activo === false) &&
        usuarios.findMaestros().filter((user) => user.activo === 1).length <= 1
      ) {
        throw conflict("No se puede desactivar o quitar el rol al último maestro");
      }
      if (
        data.matricula &&
        data.matricula !== current.matricula &&
        usuarios.findByMatricula(data.matricula)
      ) {
        throw conflict("La matrícula ya está registrada");
      }

      const { password, activo, ...fields } = data;
      const update: UpdateUsuarioData = {
        ...fields,
        ...(password
          ? { password_hash: await bcrypt.hash(password, config.bcryptRounds) }
          : {}),
        ...(activo === undefined ? {} : { activo: activo ? 1 : 0 }),
      };
      const updated = usuarios.update(id, update);
      if (!updated) throw notFound("Usuario no encontrado");
      res.json(toPublicUsuario(updated));
    }),
  );

  router.delete(
    "/:id",
    ...maestro,
    (req, res) => {
      const id = parseId(req.params.id);
      const usuario = usuarios.findById(id);
      if (!usuario) throw notFound("Usuario no encontrado");
      if (
        usuario.rol_nombre === "maestro" &&
        usuario.activo === 1 &&
        usuarios.findMaestros().filter((user) => user.activo === 1).length <= 1
      ) {
        throw conflict("No se puede eliminar al último maestro");
      }
      authService.deleteUsuario(id);
      res.status(204).send();
    },
  );

  router.patch(
    "/:id/activar",
    ...maestro,
    (req, res) => {
      const id = parseId(req.params.id);
      const { activo } = parseBody(usuarioActiveSchema, req.body);
      const usuario = usuarios.findById(id);
      if (!usuario) throw notFound("Usuario no encontrado");
      if (
        !activo &&
        usuario.rol_nombre === "maestro" &&
        usuario.activo === 1 &&
        usuarios.findMaestros().filter((user) => user.activo === 1).length <= 1
      ) {
        throw conflict("No se puede desactivar al último maestro");
      }
      if (!usuarios.toggleActivo(id, activo ? 1 : 0)) {
        throw notFound("Usuario no encontrado");
      }
      res.json({ message: activo ? "Usuario activado" : "Usuario desactivado" });
    },
  );

  return router;
}
