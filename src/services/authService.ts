import jwt from "jsonwebtoken";
import type { SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { config } from "../config/env";
import { badRequest, conflict, unauthorized } from "../errors/httpError";
import type { UserRepository, UserProfile } from "../repositories/userRepository";
import type { TokenRepository } from "../repositories/tokenRepository";
import type { StudentRepository } from "../repositories/studentRepository";
import type {
  AuthAccountKind,
  RefreshTokenRepository,
} from "../repositories/refreshTokenRepository";
import type { RolRepository } from "../repositories/rolRepository";
import type {
  UsuarioConRol,
  UsuarioRepository,
} from "../repositories/usuarioRepository";

export interface PublicUser {
  id: number;
  email: string;
  nombre?: string;
  apellido?: string;
  matricula?: string;
  apellido_paterno?: string;
  apellido_materno?: string | null;
  rol_id?: number;
  rol_nombre?: string;
}

export interface ProfileUpdate {
  nombre?: string;
  apellido?: string;
  apellido_paterno?: string;
  apellido_materno?: string | null;
}

export interface TokenPayload {
  sub: string;
  email: string;
  jti: string;
  exp: number;
  iat: number;
  kind: AuthAccountKind;
  nombre?: string;
  rol_id?: number;
  rol_nombre?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export class AuthService {
  private readonly refreshTokenExpiry = 7 * 24 * 60 * 60;

  constructor(
    private readonly users: UserRepository,
    private readonly tokens: TokenRepository,
    private readonly students: StudentRepository,
    private readonly refreshTokens: RefreshTokenRepository,
    private readonly usuarios?: UsuarioRepository,
    private readonly roles?: RolRepository,
  ) {}

  async register(
    email: string,
    password: string,
    profile: UserProfile = {},
  ): Promise<PublicUser> {
    if (
      this.users.findByEmail(email) ||
      this.usuarios?.existsByEmail(email) ||
      this.students.findByEmail(email)
    ) {
      throw conflict("Ya existe un usuario con ese correo electrónico");
    }

    const hash = await bcrypt.hash(password, config.bcryptRounds);
    const user = this.users.create(email, hash, profile);
    return this.toPublicUser(user);
  }

  async registerUsuario(data: {
    nombre: string;
    apellido_paterno: string;
    apellido_materno?: string;
    email: string;
    password: string;
    rol_id: number;
    matricula?: string;
  }): Promise<PublicUser> {
    if (!this.usuarios || !this.roles) {
      throw new Error("El registro de usuarios con roles no está configurado");
    }

    const role = this.roles.findById(data.rol_id);
    if (!role) throw badRequest("El rol indicado no existe");
    if (role.nombre !== "estudiante") {
      throw badRequest("El registro público solo permite el rol estudiante");
    }

    return this.createUsuario(data);
  }

  async createUsuario(data: {
    nombre: string;
    apellido_paterno: string;
    apellido_materno?: string;
    email: string;
    password: string;
    rol_id: number;
    matricula?: string;
  }): Promise<PublicUser> {
    if (!this.usuarios || !this.roles) {
      throw new Error("La gestión de usuarios con roles no está configurada");
    }

    this.assertUsuarioEmailAvailable(data.email);

    const role = this.roles.findById(data.rol_id);
    if (!role) throw badRequest("El rol indicado no existe");

    if (data.matricula && this.usuarios.existsByMatricula(data.matricula)) {
      throw conflict("La matrícula ya está registrada");
    }

    const passwordHash = await bcrypt.hash(data.password, config.bcryptRounds);
    const usuario = this.usuarios.create({
      nombre: data.nombre,
      apellido_paterno: data.apellido_paterno,
      apellido_materno: data.apellido_materno,
      email: data.email,
      password_hash: passwordHash,
      rol_id: role.id,
      matricula: data.matricula,
    });

    return this.toPublicUsuario(usuario);
  }

  assertUsuarioEmailAvailable(email: string, exceptUsuarioId?: number): void {
    const usuario = this.usuarios?.findByEmail(email);
    if (
      (usuario && usuario.id !== exceptUsuarioId) ||
      this.users.findByEmail(email) ||
      this.students.findByEmail(email)
    ) {
      throw conflict("Ya existe un usuario con ese correo electrónico");
    }
  }

  deleteUsuario(id: number): boolean {
    if (!this.usuarios) {
      throw new Error("La gestión de usuarios con roles no está configurada");
    }
    const deleted = this.usuarios.delete(id);
    if (deleted) this.refreshTokens.deleteByUsuario(id);
    return deleted;
  }

  async login(
    email: string,
    password: string,
  ): Promise<{ accessToken: string; refreshToken: string; user: PublicUser }> {
    const usuario = this.usuarios?.findByEmail(email);
    if (usuario) {
      if (usuario.activo !== 1) {
        throw unauthorized("Usuario inactivo. Contacta al administrador.");
      }

      const passwordMatches = await bcrypt.compare(password, usuario.password_hash);
      if (!passwordMatches) throw unauthorized("Credenciales inválidas");

      const usuarioConRol = this.usuarios?.findById(usuario.id);
      if (!usuarioConRol) throw unauthorized("Usuario no encontrado");

      const accessToken = this.generateUsuarioAccessToken(usuarioConRol);
      const refreshToken = this.refreshTokens.createForUsuario(
        usuario.id,
        this.refreshTokenExpiry,
      );
      return {
        accessToken,
        refreshToken: refreshToken.token,
        user: this.toPublicUsuario(usuarioConRol),
      };
    }

    const user = this.users.findByEmail(email);
    const student = user ? undefined : this.students.findByEmail(email);
    const account = user
      ? {
          id: user.id,
          email: user.email,
          hash: user.password_hash,
          kind: "user" as const,
          nombre: user.nombre,
          apellido: user.apellido,
          matricula: user.matricula,
        }
      : student
        ? {
            id: student.id,
            email: student.email,
            hash: student.password_hash,
            kind: "student" as const,
            nombre: student.nombre,
            apellido: student.apellido,
            matricula: student.matricula,
          }
        : undefined;

    if (!account || account.hash === "") {
      throw unauthorized("Credenciales inválidas");
    }

    const passwordMatches = await bcrypt.compare(password, account.hash);
    if (!passwordMatches) throw unauthorized("Credenciales inválidas");

    const accessToken = this.generateLegacyAccessToken(
      account.id,
      account.email,
      account.kind,
    );
    const refreshToken = this.refreshTokens.create(
      account.id,
      account.kind,
      this.refreshTokenExpiry,
    );
    const matchingStudent =
      account.kind === "user"
        ? this.students.findByEmail(account.email)
        : undefined;

    return {
      accessToken,
      refreshToken: refreshToken.token,
      user: this.toPublicUser({
        id: account.id,
        email: account.email,
        nombre: account.nombre || matchingStudent?.nombre,
        apellido: account.apellido || matchingStudent?.apellido,
        matricula: account.matricula || matchingStudent?.matricula,
      }),
    };
  }

  getProfile(payload: TokenPayload): PublicUser {
    const id = Number(payload.sub);
    if (!Number.isSafeInteger(id) || id < 1) {
      throw unauthorized("Usuario no encontrado");
    }

    if (payload.kind === "usuario") {
      const usuario = this.usuarios?.findById(id);
      if (!usuario || usuario.activo !== 1) {
        throw unauthorized("Usuario no encontrado o inactivo");
      }
      return this.toPublicUsuario(usuario);
    }

    if (payload.kind === "student") {
      const student = this.students.findById(id);
      if (!student) throw unauthorized("Usuario no encontrado");
      return this.toPublicUser(student);
    }

    const user = this.users.findById(id);
    if (!user) throw unauthorized("Usuario no encontrado");
    const matchingStudent = this.students.findByEmail(user.email);
    return this.toPublicUser({
      ...user,
      nombre: user.nombre || matchingStudent?.nombre,
      apellido: user.apellido || matchingStudent?.apellido,
      matricula: user.matricula || matchingStudent?.matricula,
    });
  }

  updateProfile(payload: TokenPayload, data: ProfileUpdate): PublicUser {
    const id = Number(payload.sub);
    if (!Number.isSafeInteger(id) || id < 1) {
      throw unauthorized("Usuario no encontrado");
    }

    if (payload.kind === "usuario") {
      if ("apellido" in data) {
        throw badRequest("Usa apellido_paterno y apellido_materno para este usuario");
      }
      const current = this.usuarios?.findById(id);
      if (!current || current.activo !== 1) {
        throw unauthorized("Usuario no encontrado o inactivo");
      }
      const updated = this.usuarios?.update(id, {
        nombre: data.nombre,
        apellido_paterno: data.apellido_paterno,
        apellido_materno: data.apellido_materno,
      });
      if (!updated) throw unauthorized("Usuario no encontrado");
      return this.toPublicUsuario(updated);
    }

    if ("apellido_paterno" in data || "apellido_materno" in data) {
      throw badRequest("Usa el campo apellido para este usuario");
    }

    if (payload.kind === "student") {
      const updated = this.students.updateProfile(id, {
        nombre: data.nombre,
        apellido: data.apellido,
      });
      if (!updated) throw unauthorized("Usuario no encontrado");
      return this.toPublicUser(updated);
    }

    const updated = this.users.updateProfile(id, {
      nombre: data.nombre,
      apellido: data.apellido,
    });
    if (!updated) throw unauthorized("Usuario no encontrado");
    const matchingStudent = this.students.findByEmail(updated.email);
    return this.toPublicUser({
      ...updated,
      nombre: updated.nombre || matchingStudent?.nombre,
      apellido: updated.apellido || matchingStudent?.apellido,
      matricula: updated.matricula || matchingStudent?.matricula,
    });
  }

  async refresh(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const validation = this.refreshTokens.isValid(refreshToken);
    if (!validation.valid || !validation.userId || !validation.userKind) {
      throw unauthorized("Refresh token inválido o expirado");
    }

    this.refreshTokens.delete(refreshToken);

    if (validation.userKind === "usuario") {
      const usuario = this.usuarios?.findById(validation.userId);
      if (!usuario || usuario.activo !== 1) {
        throw unauthorized("Usuario no encontrado o inactivo");
      }

      const accessToken = this.generateUsuarioAccessToken(usuario);
      const nextRefreshToken = this.refreshTokens.createForUsuario(
        usuario.id,
        this.refreshTokenExpiry,
      );
      return {
        accessToken,
        refreshToken: nextRefreshToken.token,
      };
    }

    const account =
      validation.userKind === "user"
        ? this.users.findById(validation.userId)
        : this.students.findById(validation.userId);

    if (!account) throw unauthorized("Usuario no encontrado");

    const accessToken = this.generateLegacyAccessToken(
      account.id,
      account.email,
      validation.userKind,
    );
    const nextRefreshToken = this.refreshTokens.create(
      account.id,
      validation.userKind,
      this.refreshTokenExpiry,
    );
    return {
      accessToken,
      refreshToken: nextRefreshToken.token,
    };
  }

  logout(payload: TokenPayload, refreshToken?: string): void {
    this.tokens.revoke(payload.jti, payload.exp);
    if (refreshToken) this.refreshTokens.delete(refreshToken);
  }

  verify(token: string): TokenPayload {
    try {
      const decoded = jwt.verify(token, config.jwtSecret) as TokenPayload;
      if (!decoded.jti) throw new Error("token sin jti");
      if (this.tokens.isRevoked(decoded.jti)) {
        throw unauthorized("La sesión ha sido cerrada");
      }
      return decoded;
    } catch (err) {
      if (err instanceof Error && err.name === "HttpError") throw err;
      throw unauthorized("Token inválido o expirado");
    }
  }

  private generateLegacyAccessToken(
    userId: number,
    email: string,
    kind: "user" | "student",
  ): string {
    const options: SignOptions = {
      expiresIn: config.jwtExpiresIn as SignOptions["expiresIn"],
      jwtid: randomUUID(),
    };
    return jwt.sign({ sub: String(userId), email, kind }, config.jwtSecret, options);
  }

  private generateUsuarioAccessToken(usuario: UsuarioConRol): string {
    const options: SignOptions = {
      expiresIn: config.jwtExpiresIn as SignOptions["expiresIn"],
      jwtid: randomUUID(),
    };
    return jwt.sign(
      {
        sub: String(usuario.id),
        email: usuario.email,
        kind: "usuario",
        nombre: usuario.nombre,
        rol_id: usuario.rol_id,
        rol_nombre: usuario.rol_nombre,
      },
      config.jwtSecret,
      options,
    );
  }

  private toPublicUser(user: {
    id: number;
    email: string;
    nombre?: string;
    apellido?: string;
    matricula?: string;
  }): PublicUser {
    return {
      id: user.id,
      email: user.email,
      ...(user.nombre ? { nombre: user.nombre } : {}),
      ...(user.apellido ? { apellido: user.apellido } : {}),
      ...(user.matricula ? { matricula: user.matricula } : {}),
    };
  }

  private toPublicUsuario(usuario: UsuarioConRol): PublicUser {
    return {
      id: usuario.id,
      nombre: usuario.nombre,
      apellido_paterno: usuario.apellido_paterno,
      apellido_materno: usuario.apellido_materno,
      email: usuario.email,
      rol_id: usuario.rol_id,
      rol_nombre: usuario.rol_nombre,
      ...(usuario.matricula ? { matricula: usuario.matricula } : {}),
    };
  }
}
