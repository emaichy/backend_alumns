import { DatabaseSync } from "node:sqlite";
import { existsSync, mkdirSync } from "node:fs";
import path from "node:path";

export type AppDatabase = DatabaseSync;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  nombre        TEXT NOT NULL DEFAULT '',
  apellido      TEXT NOT NULL DEFAULT '',
  matricula     TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS roles (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre      TEXT NOT NULL UNIQUE,
  descripcion TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS usuarios (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre           TEXT NOT NULL,
  apellido_paterno TEXT NOT NULL,
  apellido_materno TEXT,
  email            TEXT NOT NULL UNIQUE,
  password_hash    TEXT NOT NULL,
  rol_id           INTEGER NOT NULL,
  matricula        TEXT UNIQUE,
  activo           INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (rol_id) REFERENCES roles(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS students (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre        TEXT NOT NULL,
  apellido      TEXT NOT NULL,
  matricula     TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL DEFAULT '',
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti        TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  user_kind  TEXT NOT NULL CHECK (user_kind IN ('user', 'student')),
  usuario_id INTEGER,
  token      TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id, user_kind);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);
CREATE INDEX IF NOT EXISTS idx_usuarios_rol ON usuarios(rol_id);
CREATE INDEX IF NOT EXISTS idx_usuarios_matricula ON usuarios(matricula);
`;

/**
 * Crea (o abre) una base SQLite, aplica el esquema y la devuelve.
 * Usa ":memory:" para una base en memoria (útil en pruebas).
 */
export function createDatabase(location: string): AppDatabase {
  if (location !== ":memory:") {
    const dir = path.dirname(location);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  }
  const db = new DatabaseSync(location);
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(SCHEMA);

  const refreshTokenCols = db
    .prepare("PRAGMA table_info(refresh_tokens)")
    .all() as Array<{ name: string }>;
  if (!refreshTokenCols.some((column) => column.name === "usuario_id")) {
    db.exec("ALTER TABLE refresh_tokens ADD COLUMN usuario_id INTEGER");
  }
  db.exec(
    "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_usuario ON refresh_tokens(usuario_id)",
  );

  db.prepare(
    "INSERT OR IGNORE INTO roles (nombre, descripcion) VALUES (?, ?)",
  ).run("estudiante", "Rol de estudiante");
  db.prepare(
    "INSERT OR IGNORE INTO roles (nombre, descripcion) VALUES (?, ?)",
  ).run("maestro", "Rol de maestro");

  const userCols = db
    .prepare("PRAGMA table_info(users)")
    .all() as unknown as Array<{ name: string }>;
  for (const column of ["nombre", "apellido", "matricula"]) {
    if (!userCols.some((col) => col.name === column)) {
      db.exec(`ALTER TABLE users ADD COLUMN ${column} TEXT NOT NULL DEFAULT ''`);
    }
  }

  db.exec(`
    UPDATE users
    SET nombre = COALESCE(
          NULLIF(nombre, ''),
          (SELECT nombre FROM students WHERE students.email = users.email)
        ),
        apellido = COALESCE(
          NULLIF(apellido, ''),
          (SELECT apellido FROM students WHERE students.email = users.email)
        ),
        matricula = COALESCE(
          NULLIF(matricula, ''),
          (SELECT matricula FROM students WHERE students.email = users.email)
        )
    WHERE EXISTS (SELECT 1 FROM students WHERE students.email = users.email)
  `);

  // Migración: si una base existente aún no tiene la columna password_hash
  // (creada antes de este cambio), la agregamos.
  const cols = db
    .prepare("PRAGMA table_info(students)")
    .all() as unknown as Array<{ name: string }>;
  if (!cols.some((c) => c.name === "password_hash")) {
    db.exec(
      "ALTER TABLE students ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''",
    );
  }

  const studentRole = db
    .prepare("SELECT id FROM roles WHERE nombre = ?")
    .get("estudiante") as { id: number };
  const userRows = db
    .prepare("SELECT id, email, password_hash, nombre, apellido, matricula FROM users")
    .all() as Array<{
      id: number;
      email: string;
      password_hash: string;
      nombre: string;
      apellido: string;
      matricula: string;
    }>;
  const insertUsuario = db.prepare(`
    INSERT OR IGNORE INTO usuarios
      (nombre, apellido_paterno, email, password_hash, rol_id, matricula)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const user of userRows) {
    insertUsuario.run(
      user.nombre || "Usuario",
      user.apellido || "Migrado",
      user.email,
      user.password_hash,
      studentRole.id,
      user.matricula || null,
    );
  }

  const studentRows = db
    .prepare("SELECT nombre, apellido, matricula, email, password_hash FROM students")
    .all() as Array<{
      nombre: string;
      apellido: string;
      matricula: string;
      email: string;
      password_hash: string;
    }>;
  for (const student of studentRows) {
    insertUsuario.run(
      student.nombre,
      student.apellido,
      student.email,
      student.password_hash,
      studentRole.id,
      student.matricula || null,
    );
  }

  return db;
}
