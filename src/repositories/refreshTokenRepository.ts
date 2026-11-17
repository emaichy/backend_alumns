import { randomUUID } from "node:crypto";
import type { AppDatabase } from "../db/database";

export type AuthAccountKind = "user" | "student" | "usuario";

export interface RefreshTokenRecord {
  id: number;
  user_id: number;
  user_kind: "user" | "student";
  usuario_id: number | null;
  token: string;
  expires_at: number;
  created_at: number;
}

export class RefreshTokenRepository {
  constructor(private readonly db: AppDatabase) {}

  create(
    userId: number,
    userKind: "user" | "student",
    expiresInSeconds: number,
  ): { token: string; expiresAt: number } {
    const token = randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;

    this.db
      .prepare(`
        INSERT INTO refresh_tokens (user_id, user_kind, token, expires_at)
        VALUES (?, ?, ?, ?)
      `)
      .run(userId, userKind, token, expiresAt);

    return { token, expiresAt };
  }

  createForUsuario(
    usuarioId: number,
    expiresInSeconds: number,
  ): { token: string; expiresAt: number } {
    const token = randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;

    this.db
      .prepare(`
        INSERT INTO refresh_tokens (user_id, user_kind, usuario_id, token, expires_at)
        VALUES (?, 'user', ?, ?, ?)
      `)
      .run(usuarioId, usuarioId, token, expiresAt);

    return { token, expiresAt };
  }

  findByToken(token: string): RefreshTokenRecord | undefined {
    return this.db
      .prepare(`
        SELECT id, user_id, user_kind, usuario_id, token, expires_at, created_at
        FROM refresh_tokens
        WHERE token = ?
      `)
      .get(token) as RefreshTokenRecord | undefined;
  }

  delete(token: string): boolean {
    const result = this.db
      .prepare("DELETE FROM refresh_tokens WHERE token = ?")
      .run(token);
    return result.changes > 0;
  }

  deleteByUser(userId: number, userKind: "user" | "student"): number {
    const result = this.db
      .prepare(`
        DELETE FROM refresh_tokens
        WHERE user_id = ? AND user_kind = ? AND usuario_id IS NULL
      `)
      .run(userId, userKind);
    return Number(result.changes);
  }

  deleteByUsuario(usuarioId: number): number {
    const result = this.db
      .prepare("DELETE FROM refresh_tokens WHERE usuario_id = ?")
      .run(usuarioId);
    return Number(result.changes);
  }

  deleteExpired(): number {
    const now = Math.floor(Date.now() / 1000);
    const result = this.db
      .prepare("DELETE FROM refresh_tokens WHERE expires_at < ?")
      .run(now);
    return Number(result.changes);
  }

  isValid(token: string): {
    valid: boolean;
    userId?: number;
    userKind?: AuthAccountKind;
  } {
    const record = this.findByToken(token);
    if (!record) return { valid: false };

    const now = Math.floor(Date.now() / 1000);
    if (record.expires_at < now) {
      this.delete(token);
      return { valid: false };
    }

    return {
      valid: true,
      userId: record.user_id,
      userKind: record.usuario_id === null ? record.user_kind : "usuario",
    };
  }
}
