import type { AppDatabase } from "../db/database";

export interface Rol {
  id: number;
  nombre: string;
  descripcion: string | null;
  created_at: string;
}

export class RolRepository {
  constructor(private readonly db: AppDatabase) {}

  findAll(): Rol[] {
    return this.db
      .prepare("SELECT * FROM roles ORDER BY nombre")
      .all() as unknown as Rol[];
  }

  findById(id: number): Rol | undefined {
    return this.db
      .prepare("SELECT * FROM roles WHERE id = ?")
      .get(id) as Rol | undefined;
  }

  findByNombre(nombre: string): Rol | undefined {
    return this.db
      .prepare("SELECT * FROM roles WHERE nombre = ?")
      .get(nombre) as Rol | undefined;
  }

  create(nombre: string, descripcion?: string): Rol {
    const result = this.db
      .prepare("INSERT INTO roles (nombre, descripcion) VALUES (?, ?)")
      .run(nombre, descripcion ?? null);
    const rol = this.findById(Number(result.lastInsertRowid));
    if (!rol) throw new Error("No se pudo recuperar el rol creado");
    return rol;
  }

  update(id: number, nombre: string, descripcion?: string): Rol | undefined {
    this.db
      .prepare("UPDATE roles SET nombre = ?, descripcion = ? WHERE id = ?")
      .run(nombre, descripcion ?? null, id);
    return this.findById(id);
  }

  delete(id: number): boolean {
    const result = this.db
      .prepare("DELETE FROM roles WHERE id = ?")
      .run(id);
    return result.changes > 0;
  }

  existsByNombre(nombre: string): boolean {
    const result = this.db
      .prepare("SELECT COUNT(*) AS count FROM roles WHERE nombre = ?")
      .get(nombre) as { count: number };
    return result.count > 0;
  }
}
