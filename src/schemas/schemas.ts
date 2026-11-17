import { z } from "zod";

export const credentialsSchema = z.object({
  email: z.string().trim().email("El correo electrónico no es válido"),
  password: z
    .string()
    .min(6, "La contraseña debe tener al menos 6 caracteres"),
});

export const registrationSchema = credentialsSchema.extend({
  nombre: z.string().trim().optional(),
  apellido: z.string().trim().optional(),
  matricula: z.string().trim().optional(),
});

export const usuarioRegistrationSchema = z.object({
  nombre: z.string().trim().min(1, "El nombre es requerido"),
  apellido_paterno: z.string().trim().min(1, "El apellido paterno es requerido"),
  apellido_materno: z.string().trim().optional(),
  email: z.string().trim().email("Email inválido"),
  password: z.string().min(6, "La contraseña debe tener al menos 6 caracteres"),
  rol_id: z.number().int().positive("El rol_id debe ser un entero positivo"),
  matricula: z.string().trim().optional(),
});

export const usuarioCreateSchema = usuarioRegistrationSchema;

export const usuarioUpdateSchema = z.object({
  nombre: z.string().trim().min(1).optional(),
  apellido_paterno: z.string().trim().min(1).optional(),
  apellido_materno: z.string().trim().nullable().optional(),
  email: z.string().trim().email().optional(),
  password: z.string().min(6).optional(),
  rol_id: z.number().int().positive().optional(),
  matricula: z.string().trim().nullable().optional(),
  activo: z.boolean().optional(),
});

export const usuarioActiveSchema = z.object({
  activo: z.boolean(),
});

export const profileUpdateSchema = z.object({
  nombre: z.string().trim().min(1).optional(),
  apellido: z.string().trim().min(1).optional(),
  apellido_paterno: z.string().trim().min(1).optional(),
  apellido_materno: z.string().trim().min(1).nullable().optional(),
}).strict().refine(
  (profile) => Object.values(profile).some((value) => value !== undefined),
  { message: "Debes proporcionar al menos un campo para actualizar" },
);

export const rolSchema = z.object({
  nombre: z.string().trim().min(1, "El nombre del rol es requerido"),
  descripcion: z.string().trim().optional(),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token requerido"),
});

export const studentSchema = z.object({
  nombre: z.string().trim().min(1, "El nombre es obligatorio"),
  apellido: z.string().trim().min(1, "El apellido es obligatorio"),
  matricula: z.string().trim().min(1, "La matrícula es obligatoria"),
  email: z.string().trim().email("El correo electrónico no es válido"),
  password: z
    .string()
    .min(6, "La contraseña debe tener al menos 6 caracteres"),
});

export const studentUpdateSchema = studentSchema.extend({
  password: studentSchema.shape.password.optional(),
});

export type Credentials = z.infer<typeof credentialsSchema>;
export type RegistrationPayload = z.infer<typeof registrationSchema>;
export type UsuarioRegistrationPayload = z.infer<typeof usuarioRegistrationSchema>;
export type StudentPayload = z.infer<typeof studentSchema>;
export type StudentUpdatePayload = z.infer<typeof studentUpdateSchema>;
