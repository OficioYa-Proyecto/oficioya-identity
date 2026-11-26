package eci.edu.dosw.identity.controller;

import eci.edu.dosw.identity.dto.InternalDtos.AuthenticateRequest;
import eci.edu.dosw.identity.dto.InternalDtos.ChangePasswordRequest;
import eci.edu.dosw.identity.dto.InternalDtos.CreateCredentialRequest;
import eci.edu.dosw.identity.dto.InternalDtos.OtpResponse;
import eci.edu.dosw.identity.dto.InternalDtos.ResetPasswordRequest;
import eci.edu.dosw.identity.dto.InternalDtos.TokenResponse;
import eci.edu.dosw.identity.dto.InternalDtos.ValidatePasswordRequest;
import eci.edu.dosw.identity.service.CredentialService;
import eci.edu.dosw.identity.service.JwtProvider;
import eci.edu.dosw.identity.service.OtpService;
import eci.edu.dosw.identity.service.PasswordPolicyService;
import eci.edu.dosw.identity.service.PasswordRecoveryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * API interna de Identity: solo la consume el orquestador (rol SERVICE).
 * Identity solo autentica; no conoce perfiles de usuario ni envía notificaciones.
 */
@Tag(name = "Identity Interno", description = "Operaciones internas de credenciales, autenticación y OTP (consumidas por el Orquestador)")
@RestController
@RequestMapping("/internal/v1")
public class InternalIdentityController {

    private final CredentialService credentialService;
    private final OtpService otpService;
    private final PasswordPolicyService passwordPolicy;
    private final PasswordRecoveryService recoveryService;
    private final JwtProvider jwtProvider;

    public InternalIdentityController(CredentialService credentialService,
            OtpService otpService,
            PasswordPolicyService passwordPolicy,
            PasswordRecoveryService recoveryService,
            JwtProvider jwtProvider) {
        this.credentialService = credentialService;
        this.otpService = otpService;
        this.passwordPolicy = passwordPolicy;
        this.recoveryService = recoveryService;
        this.jwtProvider = jwtProvider;
    }

    @Operation(summary = "Validar política de contraseña", description = "Verifica que una contraseña cumpla con las reglas de longitud (mínimo 8 caracteres) y complejidad (mayúscula, minúscula, dígito y caracter especial).")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Contraseña válida"),
        @ApiResponse(responseCode = "400", description = "La contraseña no cumple la política de seguridad")
    })
    @PostMapping("/credentials/validate-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void validatePassword(@Valid @RequestBody ValidatePasswordRequest request) {
        passwordPolicy.validate(request.password());
    }

    @Operation(summary = "Crear credencial para usuario", description = "Genera el hash BCrypt con sal aleatoria y almacena la credencial asociada al userId.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Credencial creada exitosamente"),
        @ApiResponse(responseCode = "400", description = "Contraseña no válida según política"),
        @ApiResponse(responseCode = "409", description = "Ya existe una credencial para este correo o userId")
    })
    @PostMapping("/credentials")
    @ResponseStatus(HttpStatus.CREATED)
    public void createCredential(@Valid @RequestBody CreateCredentialRequest request) {
        credentialService.create(request.userId(), request.email(), request.password());
    }

    @Operation(summary = "Eliminar credencial de usuario", description = "Borra la credencial de forma permanente (usado para compensaciones de saga o eliminación de cuenta).")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Credencial eliminada exitosamente"),
        @ApiResponse(responseCode = "404", description = "Credencial no encontrada")
    })
    @DeleteMapping("/credentials/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteCredential(
            @Parameter(description = "UUID del usuario titular de la credencial", required = true)
            @PathVariable UUID userId) {
        credentialService.delete(userId);
    }

    @Operation(summary = "Autenticar credencial y emitir JWT", description = "Verifica la contraseña contra el hash almacenado, controla el contador de intentos fallidos (bloqueo tras 3 intentos) y emite un JWT firmado.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Autenticación exitosa, token emitido"),
        @ApiResponse(responseCode = "401", description = "Contraseña incorrecta o usuario no encontrado"),
        @ApiResponse(responseCode = "423", description = "Cuenta bloqueada temporalmente por exceso de intentos fallidos")
    })
    @PostMapping("/auth/login")
    public TokenResponse login(@Valid @RequestBody AuthenticateRequest request) {
        credentialService.authenticate(request.userId(), request.password());
        String token = jwtProvider.generateToken(request.userId(), request.roles());
        return new TokenResponse(token, jwtProvider.getExpirationSeconds());
    }

    @Operation(summary = "Cambiar contraseña de usuario", description = "Verifica la contraseña actual, valida la nueva contraseña y actualiza el hash en la base de datos.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Contraseña cambiada exitosamente"),
        @ApiResponse(responseCode = "400", description = "Nueva contraseña débil o igual a la actual"),
        @ApiResponse(responseCode = "401", description = "Contraseña actual incorrecta"),
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    @PutMapping("/credentials/{userId}/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void changePassword(
            @Parameter(description = "UUID del usuario", required = true)
            @PathVariable UUID userId,
            @Valid @RequestBody ChangePasswordRequest request) {
        credentialService.changePassword(userId, request.currentPassword(), request.newPassword());
    }

    @Operation(summary = "Generar código OTP para recuperación", description = "Genera un código numérico aleatorio de 6 dígitos con hash SHA-256 en memoria, validez de 10 minutos y rate limit.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Código OTP generado exitosamente"),
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado"),
        @ApiResponse(responseCode = "429", description = "Debe esperar antes de solicitar un nuevo código (rate limit)")
    })
    @PostMapping("/credentials/{userId}/otp")
    public OtpResponse generateOtp(
            @Parameter(description = "UUID del usuario que solicita recuperación", required = true)
            @PathVariable UUID userId) {
        return new OtpResponse(otpService.generate(userId), OtpService.VALID_MINUTES);
    }

    @Operation(summary = "Restablecer contraseña usando código OTP", description = "Valida el código OTP ingresado, aplica la nueva contraseña y resetea los contadores de intentos fallidos.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Contraseña restablecida exitosamente"),
        @ApiResponse(responseCode = "400", description = "Código inválido/expirado o contraseña débil"),
        @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    @PostMapping("/credentials/{userId}/password/reset")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(
            @Parameter(description = "UUID del usuario que restablece la contraseña", required = true)
            @PathVariable UUID userId,
            @Valid @RequestBody ResetPasswordRequest request) {
        recoveryService.reset(userId, request.code(), request.newPassword());
    }
}
