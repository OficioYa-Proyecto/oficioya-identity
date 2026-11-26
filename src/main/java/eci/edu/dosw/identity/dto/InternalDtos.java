package eci.edu.dosw.identity.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.UUID;

/**
 * Contratos (request/response) de la API interna de Identity,
 * usada únicamente por el orquestador.
 */
public final class InternalDtos {

    private InternalDtos() {
    }

    @Schema(description = "Petición interna para validar si una contraseña cumple la política de seguridad")
    public record ValidatePasswordRequest(
            @Schema(description = "Contraseña en texto plano a verificar", example = "Segura#2026!Ab", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String password) {
    }

    @Schema(description = "Petición interna para crear la credencial de un usuario nuevo (hasheo seguro)")
    public record CreateCredentialRequest(
            @Schema(description = "UUID del usuario generado por el dominio de usuarios", example = "717cfb45-903b-4825-8c97-fb54e98b5bd9", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotNull UUID userId,

            @Schema(description = "Correo electrónico único de la credencial", example = "usuario@gmail.com", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank @Email String email,

            @Schema(description = "Contraseña que será hasheada con BCrypt", example = "Segura#2026!Ab", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String password) {
    }

    @Schema(description = "Petición interna para autenticar credenciales y solicitar emisión de JWT")
    public record AuthenticateRequest(
            @Schema(description = "UUID del usuario a autenticar", example = "717cfb45-903b-4825-8c97-fb54e98b5bd9", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotNull UUID userId,

            @Schema(description = "Contraseña ingresada por el usuario", example = "Segura#2026!Ab", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String password,

            @Schema(description = "Roles asignados al usuario que se incluirán en los claims del token", example = "[\"CONTRATANTE\"]")
            List<String> roles) {
    }

    @Schema(description = "Respuesta con el token JWT generado y su vigencia")
    public record TokenResponse(
            @Schema(description = "Token de autenticación JWT firmado", example = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9...")
            String token,

            @Schema(description = "Tiempo de expiración en segundos", example = "900")
            long expiresIn) {
    }

    @Schema(description = "Petición interna para cambio de contraseña validando la actual")
    public record ChangePasswordRequest(
            @Schema(description = "Contraseña actual para verificación", example = "ActualPassword123*", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String currentPassword,

            @Schema(description = "Nueva contraseña a aplicar", example = "NuevaSegura#2026!Ab", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String newPassword) {
    }

    @Schema(description = "Respuesta con el código OTP generado")
    public record OtpResponse(
            @Schema(description = "Código numérico de 6 dígitos generado aleatoriamente", example = "849201")
            String code,

            @Schema(description = "Minutos de validez del código antes de expirar", example = "10")
            int validMinutes) {
    }

    @Schema(description = "Petición interna para restablecer contraseña con código OTP")
    public record ResetPasswordRequest(
            @Schema(description = "Código OTP de 6 dígitos recibido por el usuario", example = "849201", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String code,

            @Schema(description = "Nueva contraseña que cumple la política de seguridad", example = "NuevaSegura#2026!Ab", requiredMode = Schema.RequiredMode.REQUIRED)
            @NotBlank String newPassword) {
    }
}
