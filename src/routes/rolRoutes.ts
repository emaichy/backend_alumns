import { Router } from "express";
import { requireAuth, requireRole } from "../middleware/auth";
import { badRequest, conflict, notFound } from "../errors/httpError";
import { parseBody } from "../middleware/validate";
import { rolSchema } from "../schemas/schemas";
import type { AuthService } from "../services/authService";
import type { RolRepository } from "../repositories/rolRepository";
import type { UsuarioRepository } from "../repositories/usuarioRepository";

function parseId(value: string): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id < 1) {
    throw badRequest("El id debe ser un entero positivo");
  }
  return id;
}

export function createRolRouter(
  roles: RolRepository,
  usuarios: UsuarioRepository,
  authService: AuthService,
): Router {
  const router = Router();
  const auth = requireAuth(authService);
  const maestro = [auth, requireRole(authService, "maestro")];

  router.get("/", auth, (_req, res) => {
    res.json(roles.findAll());
  });

  router.get("/:id", auth, (req, res) => {
    const rol = roles.findById(parseId(req.params.id));
    if (!rol) throw notFound("Rol no encontrado");
    res.json(rol);
  });

  router.post(
    "/",
    ...maestro,
    (req, res) => {
      const data = parseBody(rolSchema, req.body);
      if (roles.existsByNombre(data.nombre)) {
        throw conflict("Ya existe un rol con ese nombre");
      }
      res.status(201).json(roles.create(data.nombre, data.descripcion));
    },
  );

  router.put(
    "/:id",
    ...maestro,
    (req, res) => {
      const id = parseId(req.params.id);
      const current = roles.findById(id);
      if (!current) throw notFound("Rol no encontrado");
      if (current.nombre === "maestro" || current.nombre === "estudiante") {
        throw conflict("No se pueden modificar los roles predeterminados");
      }

      const data = parseBody(rolSchema, req.body);
      const sameName = roles.findByNombre(data.nombre);
      if (sameName && sameName.id !== id) {
        throw conflict("Ya existe un rol con ese nombre");
      }

      const updated = roles.update(id, data.nombre, data.descripcion);
      if (!updated) throw notFound("Rol no encontrado");
      res.json(updated);
    },
  );

  router.delete(
    "/:id",
    ...maestro,
    (req, res) => {
      const id = parseId(req.params.id);
      const role = roles.findById(id);
      if (!role) throw notFound("Rol no encontrado");
      if (role.nombre === "maestro" || role.nombre === "estudiante") {
        throw conflict("No se pueden eliminar los roles predeterminados");
      }
      if (usuarios.findByRol(id).length > 0) {
        throw conflict("No se puede eliminar un rol asignado a usuarios");
      }
      roles.delete(id);
      res.status(204).send();
    },
  );

  return router;
}
