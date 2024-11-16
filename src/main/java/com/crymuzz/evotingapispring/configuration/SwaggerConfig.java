package com.crymuzz.evotingapispring.configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;


@OpenAPIDefinition(
        info = @Info(
                title = "API EVOTING WITH BLOCKCHAIN",
                description = "Sistema de votación electrónica que permite a los usuarios, principalmente " +
                        "estudiantes, participar en elecciones de forma segura y sencilla. Los usuarios pueden " +
                        "iniciar sesión y votar por candidatos en elecciones activas. Los roles " +
                        "asignados (como administrado o estudiante) determinan los permisos de cada usuario.",
                termsOfService = "https://upao.edu.pe/",
                version = "1.0.0", contact = @Contact(
                name = "Favio Facundo",
                url = "git.",
                email = "favioangulo2002@gmail.com"),
                license = @License(
                        name = "Standard Software Use License for CryMuZz",
                        url = "git."
                )

        ),
        servers = {@Server(
                description = "DEV SERVER",
                url = "http://localhost:8080"
        ), @Server(
                description = "PRODUCTION SERVER",
                url = "http://localhost:8080"
        )},
        security = @SecurityRequirement(
                name = "Security Token"
        )
)
@SecurityScheme(
        name = "Security Token",
        description = "Token de acceso para la API",
        type = SecuritySchemeType.HTTP,
        paramName = HttpHeaders.AUTHORIZATION,
        in = SecuritySchemeIn.HEADER,
        scheme = "bearer",
        bearerFormat = "JWT"
)
public class SwaggerConfig {

}
