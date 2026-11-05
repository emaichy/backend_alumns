import type { AppDatabase } from "../db/database";

export interface UserRow {
  id: number;
  email: string;
  password_hash: string;
  nombre: string;
  apellido: string;
  matricula: string;
  created_at: string;
}

export interface UserProfile {
  nombre?: string;
  apellido?: string;
  matricula?: string;
}

export class UserRepository {
  constructor(private readonly db: AppDatabase) {}

  create(email: string, passwordHash: string, profile: UserProfile = {}): UserRow {
    const stmt = this.db.prepare(
      `INSERT INTO users (email, password_hash, nombre, apellido, matricula)
       VALUES (?, ?, ?, ?, ?)`,
    );
    const info = stmt.run(
      email,
      passwordHash,
      profile.nombre ?? "",
      profile.apellido ?? "",
      profile.matricula ?? "",
    );
    return this.findById(Number(info.lastInsertRowid))!;
  }

  findByEmail(email: string): UserRow | undefined {
    return this.db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(email) as UserRow | undefined;
  }

  findById(id: number): UserRow | undefined {
    return this.db
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(id) as UserRow | undefined;
  }
}
