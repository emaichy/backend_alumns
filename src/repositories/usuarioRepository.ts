import type { AppDatabase } from "../db/database";

export interface Usuario {
  id: number;
  nombre: string;
  apellido_paterno: string;
  apellido_materno: string | null;
  email: string;
  password_hash: string;
  rol_id: number;
  matricula: string | null;
  activo: number;
  created_at: string;
  updated_at: string;
}

export interface UsuarioConRol extends Usuario {
  rol_nombre: string;
  rol_descripcion: string | null;
}

export interface CreateUsuarioData {
  nombre: string;
  apellido_paterno: string;
  apellido_materno?: string;
  email: string;
  password_hash: string;
  rol_id: number;
  matricula?: string;
}

export interface UpdateUsuarioData {
  nombre?: string;
  apellido_paterno?: string;
  apellido_materno?: string | null;
  email?: string;
  password_hash?: string;
  rol_id?: number;
  matricula?: string | null;
  activo?: number;
}

const WITH_ROLE = `
  SELECT u.*, r.nombre AS rol_nombre, r.descripcion AS rol_descripcion
  FROM usuarios u
  INNER JOIN roles r ON u.rol_id = r.id
`;

export class UsuarioRepository {
  constructor(private readonly db: AppDatabase) {}

  findAll(): UsuarioConRol[] {
    return this.db
      .prepare(`${WITH_ROLE} ORDER BY u.apellido_paterno, u.nombre`)
      .all() as unknown as UsuarioConRol[];
  }

  findById(id: number): UsuarioConRol | undefined {
    return this.db
      .prepare(`${WITH_ROLE} WHERE u.id = ?`)
      .get(id) as UsuarioConRol | undefined;
  }

  findByEmail(email: string): Usuario | undefined {
    return this.db
      .prepare("SELECT * FROM usuarios WHERE email = ?")
      .get(email) as Usuario | undefined;
  }

  findByMatricula(matricula: string): Usuario | undefined {
    return this.db
      .prepare("SELECT * FROM usuarios WHERE matricula = ?")
      .get(matricula) as Usuario | undefined;
  }

  findByRol(rolId: number): UsuarioConRol[] {
    return this.db
      .prepare(`${WITH_ROLE} WHERE u.rol_id = ? ORDER BY u.apellido_paterno, u.nombre`)
      .all(rolId) as unknown as UsuarioConRol[];
  }

  findEstudiantes(): UsuarioConRol[] {
    return this.findByRoleName("estudiante");
  }

  findMaestros(): UsuarioConRol[] {
    return this.findByRoleName("maestro");
  }

  findActivos(): UsuarioConRol[] {
    return this.db
      .prepare(`${WITH_ROLE} WHERE u.activo = 1 ORDER BY u.apellido_paterno, u.nombre`)
      .all() as unknown as UsuarioConRol[];
  }

  search(query: string): UsuarioConRol[] {
    const term = `%${query}%`;
    return this.db
      .prepare(`
        ${WITH_ROLE}
        WHERE u.nombre LIKE ? OR u.apellido_paterno LIKE ? OR u.email LIKE ?
        ORDER BY u.apellido_paterno, u.nombre
      `)
      .all(term, term, term) as unknown as UsuarioConRol[];
  }

  create(data: CreateUsuarioData): UsuarioConRol {
    const result = this.db
      .prepare(`
        INSERT INTO usuarios
          (nombre, apellido_paterno, apellido_materno, email, password_hash, rol_id, matricula)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        data.nombre,
        data.apellido_paterno,
        data.apellido_materno ?? null,
        data.email,
        data.password_hash,
        data.rol_id,
        data.matricula ?? null,
      );
    const usuario = this.findById(Number(result.lastInsertRowid));
    if (!usuario) throw new Error("No se pudo recuperar el usuario creado");
    return usuario;
  }

  update(id: number, data: UpdateUsuarioData): UsuarioConRol | undefined {
    const fields: string[] = [];
    const values: Array<string | number | null> = [];

    const addField = (
      field: string,
      value: string | number | null | undefined,
    ) => {
      if (value !== undefined) {
        fields.push(`${field} = ?`);
        values.push(value);
      }
    };

    addField("nombre", data.nombre);
    addField("apellido_paterno", data.apellido_paterno);
    addField("apellido_materno", data.apellido_materno);
    addField("email", data.email);
    addField("password_hash", data.password_hash);
    addField("rol_id", data.rol_id);
    addField("matricula", data.matricula);
    addField("activo", data.activo);

    if (fields.length === 0) return this.findById(id);

    fields.push("updated_at = datetime('now')");
    values.push(id);
    this.db
      .prepare(`UPDATE usuarios SET ${fields.join(", ")} WHERE id = ?`)
      .run(...values);
    return this.findById(id);
  }

  delete(id: number): boolean {
    const result = this.db
      .prepare("DELETE FROM usuarios WHERE id = ?")
      .run(id);
    return result.changes > 0;
  }

  existsByEmail(email: string): boolean {
    const result = this.db
      .prepare("SELECT COUNT(*) AS count FROM usuarios WHERE email = ?")
      .get(email) as { count: number };
    return result.count > 0;
  }

  existsByMatricula(matricula: string): boolean {
    const result = this.db
      .prepare("SELECT COUNT(*) AS count FROM usuarios WHERE matricula = ?")
      .get(matricula) as { count: number };
    return result.count > 0;
  }

  toggleActivo(id: number, activo: number): boolean {
    const result = this.db
      .prepare("UPDATE usuarios SET activo = ?, updated_at = datetime('now') WHERE id = ?")
      .run(activo, id);
    return result.changes > 0;
  }

  private findByRoleName(nombre: string): UsuarioConRol[] {
    return this.db
      .prepare(`
        ${WITH_ROLE}
        WHERE r.nombre = ?
        ORDER BY u.apellido_paterno, u.nombre
      `)
      .all(nombre) as unknown as UsuarioConRol[];
  }
}
