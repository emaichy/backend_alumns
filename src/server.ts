import bcrypt from "bcryptjs";
import { createApp } from "./app";
import { createDatabase } from "./db/database";
import { config } from "./config/env";
import { RolRepository } from "./repositories/rolRepository";
import { UsuarioRepository } from "./repositories/usuarioRepository";

async function startServer(): Promise<void> {
  const db = createDatabase(config.dbPath);
  const { bootstrapMasterEmail: email, bootstrapMasterPassword: password } =
    config;

  if (Boolean(email) !== Boolean(password)) {
    throw new Error(
      "BOOTSTRAP_MASTER_EMAIL y BOOTSTRAP_MASTER_PASSWORD deben configurarse juntos",
    );
  }

  if (email && password) {
    if (password.length < 12) {
      throw new Error("BOOTSTRAP_MASTER_PASSWORD debe tener al menos 12 caracteres");
    }

    const usuarios = new UsuarioRepository(db);
    if (!usuarios.findMaestros().some((usuario) => usuario.activo === 1)) {
      if (usuarios.existsByEmail(email)) {
        throw new Error(
          "El correo de bootstrap ya existe con un rol que no es maestro",
        );
      }

      const maestroRole = new RolRepository(db).findByNombre("maestro");
      if (!maestroRole) throw new Error("No se encontró el rol maestro");
      const passwordHash = await bcrypt.hash(password, config.bcryptRounds);
      usuarios.create({
        nombre: "Administrador",
        apellido_paterno: "Inicial",
        email,
        password_hash: passwordHash,
        rol_id: maestroRole.id,
      });
    }
  }

  const app = createApp(db);
  app.listen(config.port, () => {
    // eslint-disable-next-line no-console
    console.log(`API de estudiantes escuchando en http://localhost:${config.port}`);
  });
}

void startServer().catch((error: unknown) => {
  // eslint-disable-next-line no-console
  console.error("No se pudo iniciar la API:", error);
  process.exitCode = 1;
});
