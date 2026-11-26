package eci.edu.dosw.identity.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Configuración OpenAPI / Swagger para el Microservicio de Identidad de OficioYa.
 * Expone la documentación de la API interna para la gestión segura de credenciales y JWT.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";
        return new OpenAPI()
                .info(new Info()
                        .title("OficioYa - Microservicio de Identidad")
                        .version("1.0.0")
                        .description("""
                                Microservicio interno de Identidad y Seguridad para OficioYa (RNF-06).
                                
                                Provee los contratos internos para:
                                - **Validación de Políticas:** Longitud, mayúsculas, minúsculas, números y caracteres especiales.
                                - **Gestión de Credenciales:** Creación (BCrypt con sal aleatoria), eliminación y cambio de contraseñas.
                                - **Autenticación y Emisión de JWT:** Validación de contraseñas, control de intentos fallidos con bloqueo temporal y generación de tokens de acceso firmados (HMAC-SHA).
                                - **Recuperación por OTP:** Generación y validación de códigos de 6 dígitos con expiración y límite de tasa.
                                """)
                        .contact(new Contact()
                                .name("Equipo OficioYa - Escuela Colombiana de Ingeniería")
                                .email("soporte@oficioya.com"))
                        .license(new License().name("MIT").url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server().url("https://oficioya-identity-api-a9dbb8dabpg0fxgk.chilecentral-01.azurewebsites.net").description("Entorno de Producción en Azure"),
                        new Server().url("http://localhost:8085").description("Entorno de Desarrollo Local")
                ))
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("Ingrese token de servicio o JWT con prefijo 'Bearer '")));
    }
}
