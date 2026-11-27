package eci.edu.dosw.identity.controller;

import eci.edu.dosw.identity.exception.AccountLockedException;
import eci.edu.dosw.identity.exception.DuplicateUserException;
import eci.edu.dosw.identity.exception.InvalidCredentialsException;
import eci.edu.dosw.identity.exception.InvalidOtpException;
import eci.edu.dosw.identity.exception.OtpRateLimitException;
import eci.edu.dosw.identity.exception.UserNotFoundException;
import eci.edu.dosw.identity.exception.WeakPasswordException;
import eci.edu.dosw.identity.model.Credential;
import eci.edu.dosw.identity.model.Otp;
import eci.edu.dosw.identity.model.OtpPurpose;
import eci.edu.dosw.identity.repository.CredentialRepository;
import eci.edu.dosw.identity.repository.OtpRepository;
import eci.edu.dosw.identity.service.JwtProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Constructor;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class InternalIdentityControllerTest {

    private static final UUID USER_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final String CLAVE = "Segura#Clave2026";
    private static final String NUEVA_CLAVE = "Nueva#Clave2026!";
    private static final String VALIDATE = "/internal/v1/credentials/validate-password";

    @Autowired
    private MockMvc mvc;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private OtpRepository otpRepository;

    @BeforeEach
    @AfterEach
    void limpiar() {
        otpRepository.deleteAll();
        credentialRepository.deleteAll();
    }

    private String servicio() {
        return "Bearer " + jwtProvider.generateServiceToken();
    }

    private String json(String password) {
        return "{\"password\":\"" + password + "\"}";
    }

    private void crearCredencialBase() throws Exception {
        mvc.perform(post("/internal/v1/credentials").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"email\":\"carlos@oficioya.com\",\"password\":\"" + CLAVE + "\"}"))
                .andExpect(status().isCreated());
    }

    @Test
    void sinTokenResponde401() throws Exception {
        mvc.perform(post(VALIDATE).contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenDeUsuarioResponde401() throws Exception {
        String tokenUsuario = "Bearer " + jwtProvider.generateToken(USER_ID, List.of("ADMIN"));
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, tokenUsuario)
                .contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenBasuraResponde401() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, "Bearer no.es.un.jwt")
                .contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void contrasenaDebilResponde400() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(json("123")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void contrasenaFuerteResponde204() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(json(CLAVE)))
                .andExpect(status().isNoContent());
    }

    @Test
    void rutaNoInternaSeDeniegaAunConTokenDeServicio() throws Exception {
        mvc.perform(get("/api/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isForbidden());
    }

    @Test
    void crearCredencialYAutenticar() throws Exception {
        crearCredencialBase();

        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"password\":\"" + CLAVE + "\",\"roles\":[\"CONTRATANTE\"]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.expiresIn").isNumber());
    }

    @Test
    void loginConClaveIncorrectaResponde401() throws Exception {
        crearCredencialBase();

        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"password\":\"Otra#Clave9999\",\"roles\":[\"CONTRATANTE\"]}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void elTokenDeUsuarioNuncaLlevaRolServicio() throws Exception {
        crearCredencialBase();

        String cuerpo = mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"password\":\"" + CLAVE + "\",\"roles\":[\"SERVICE\",\"CONTRATANTE\"]}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = cuerpo.replaceAll(".*\"token\":\"([^\"]+)\".*", "$1");
        List<String> roles = jwtProvider.getRolesFromToken(token);
        assertTrue(roles.contains("CONTRATANTE"));
        assertFalse(roles.contains("SERVICE"));
    }

    @Test
    void crearCredencialDuplicadaResponde409() throws Exception {
        crearCredencialBase();

        mvc.perform(post("/internal/v1/credentials").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"" + USER_ID + "\",\"email\":\"carlos@oficioya.com\",\"password\":\"" + CLAVE + "\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void validacionDeBodyInvalidoResponde400() throws Exception {
        mvc.perform(post(VALIDATE).header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginBloqueaCuentaTrasTresIntentosFallidosYResponde423() throws Exception {
        crearCredencialBase();
        String badLogin = "{\"userId\":\"" + USER_ID + "\",\"password\":\"Mala#Clave9999\",\"roles\":[\"CONTRATANTE\"]}";

        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/internal/v1/auth/login").header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON).content(badLogin))
                .andExpect(status().isLocked());
    }

    @Test
    void cambiarContrasenaYBorrarCredencial() throws Exception {
        crearCredencialBase();

        mvc.perform(put("/internal/v1/credentials/" + USER_ID + "/password")
                .header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"" + CLAVE + "\",\"newPassword\":\"" + NUEVA_CLAVE + "\"}"))
                .andExpect(status().isNoContent());

        mvc.perform(delete("/internal/v1/credentials/" + USER_ID)
                .header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isNoContent());
    }

    @Test
    void generarOtpUsuarioNoExistenteResponde404() throws Exception {
        UUID inexistente = UUID.fromString("99999999-9999-9999-9999-999999999999");
        mvc.perform(post("/internal/v1/credentials/" + inexistente + "/otp")
                .header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isNotFound());
    }

    @Test
    void generarOtpRestablecerClaveYErroresDeOtp() throws Exception {
        crearCredencialBase();

        String otpJson = mvc.perform(post("/internal/v1/credentials/" + USER_ID + "/otp")
                .header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        String code = otpJson.replaceAll(".*\"code\":\"([^\"]+)\".*", "$1");

        // Intento con OTP incorrecto -> 400
        mvc.perform(post("/internal/v1/credentials/" + USER_ID + "/password/reset")
                .header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"000000\",\"newPassword\":\"" + NUEVA_CLAVE + "\"}"))
                .andExpect(status().isBadRequest());

        // Intento con OTP correcto -> 204
        mvc.perform(post("/internal/v1/credentials/" + USER_ID + "/password/reset")
                .header(HttpHeaders.AUTHORIZATION, servicio())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"" + code + "\",\"newPassword\":\"" + NUEVA_CLAVE + "\"}"))
                .andExpect(status().isNoContent());

        // Superar límite de 3 OTPs por hora -> 429
        mvc.perform(post("/internal/v1/credentials/" + USER_ID + "/otp").header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isOk());
        mvc.perform(post("/internal/v1/credentials/" + USER_ID + "/otp").header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isOk());
        mvc.perform(post("/internal/v1/credentials/" + USER_ID + "/otp").header(HttpHeaders.AUTHORIZATION, servicio()))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void globalExceptionHandlerSinErroresDeCampoUsaMensajePorDefecto() throws Exception {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        BeanPropertyBindingResult binding = new BeanPropertyBindingResult(new Object(), "target");
        MethodParameter param = new MethodParameter(
                InternalIdentityController.class.getDeclaredMethod("validatePassword",
                        eci.edu.dosw.identity.dto.InternalDtos.ValidatePasswordRequest.class), 0);
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(param, binding);
        var resp = handler.handleValidation(ex);
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertNotNull(resp.getBody());
    }

    @Test
    void constructoresDeExcepcionesYModelos() throws Exception {
        assertEquals("m1", new AccountLockedException("m1").getMessage());
        assertNotNull(new AccountLockedException().getMessage());
        assertEquals("m2", new DuplicateUserException("m2").getMessage());
        assertNotNull(new DuplicateUserException().getMessage());
        assertEquals("m3", new InvalidCredentialsException("m3").getMessage());
        assertNotNull(new InvalidCredentialsException().getMessage());
        assertEquals("m4", new InvalidOtpException("m4").getMessage());
        assertNotNull(new InvalidOtpException().getMessage());
        assertEquals("m5", new OtpRateLimitException("m5").getMessage());
        assertNotNull(new OtpRateLimitException().getMessage());
        assertEquals("m6", new UserNotFoundException("m6").getMessage());
        assertNotNull(new UserNotFoundException().getMessage());
        assertEquals("m7", new WeakPasswordException("m7").getMessage());
        assertNotNull(new WeakPasswordException().getMessage());

        LocalDateTime now = LocalDateTime.now();
        Credential c1 = new Credential(USER_ID, "hash", now);
        assertEquals(USER_ID, c1.getUserId());
        assertNotNull(c1.getId());

        Credential c2 = new Credential(null, null, "a@b.com", "hash", now);
        assertNotNull(c2.getId());
        assertEquals(c2.getId(), c2.getUserId());

        Constructor<Credential> ctorCred = Credential.class.getDeclaredConstructor();
        ctorCred.setAccessible(true);
        Credential cEmpty = ctorCred.newInstance();
        cEmpty.setId(USER_ID);
        assertEquals(USER_ID, cEmpty.getUserId());

        Credential cEmpty2 = ctorCred.newInstance();
        cEmpty2.setUserId(USER_ID);
        assertEquals(USER_ID, cEmpty2.getId());
        cEmpty2.setId(USER_ID);
        cEmpty2.setUserId(USER_ID);
        cEmpty2.setEmail("x@y.com");
        cEmpty2.setPasswordHash("h2");
        cEmpty2.setFailedAttempts(2);
        cEmpty2.setLockedUntil(now);
        cEmpty2.setLastLogin(now);
        cEmpty2.setPasswordChangedAt(now);
        assertEquals("x@y.com", cEmpty2.getEmail());
        assertEquals("h2", cEmpty2.getPasswordHash());
        assertEquals(2, cEmpty2.getFailedAttempts());
        assertEquals(now, cEmpty2.getLockedUntil());
        assertEquals(now, cEmpty2.getLastLogin());
        assertEquals(now, cEmpty2.getPasswordChangedAt());

        Constructor<Otp> ctorOtp = Otp.class.getDeclaredConstructor();
        ctorOtp.setAccessible(true);
        Otp otpEmpty = ctorOtp.newInstance();
        assertNull(otpEmpty.getId());

        Otp otp = new Otp(USER_ID, "chash", OtpPurpose.RESET_PASSWORD, now, now.plusMinutes(10));
        otp.setAttempts(1);
        otp.setUsed(true);
        assertNull(otp.getId());
        assertEquals(USER_ID, otp.getUserId());
        assertEquals("chash", otp.getCodeHash());
        assertEquals(OtpPurpose.RESET_PASSWORD, otp.getPurpose());
        assertEquals(now, otp.getCreatedAt());
        assertEquals(now.plusMinutes(10), otp.getExpiresAt());
        assertEquals(1, otp.getAttempts());
        assertTrue(otp.isUsed());
    }
}
