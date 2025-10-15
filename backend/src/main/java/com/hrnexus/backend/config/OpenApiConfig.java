package com.hrnexus.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

/**
 * Configuration class for customising the generated OpenAPI (Swagger)
 * documentation.
 */
@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME_NAME = "OAuth2 - Username/Password";
    private static final String TOKEN_URL = "api/v1/auth/login";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME_NAME))
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME_NAME, new SecurityScheme()
                                .name(SECURITY_SCHEME_NAME)
                                .type(SecurityScheme.Type.OAUTH2)
                                .description("Use Username and Password to obtain a JWT.")
                                .flows(new OAuthFlows()
                                        // Configure the Password Grant flow
                                        .password(new OAuthFlow()
                                                // CRITICAL: This URL MUST point to the login endpoint that returns a JWT
                                                .tokenUrl(TOKEN_URL)
                                                // Scopes are optional for basic authentication but required for the OAuthFlow object
                                                .scopes(new Scopes())
                                        )
                                )
                        )
                )
                .info(new Info()
                        .title("HR Nexus Backend API")
                        .version("1.0.0")
                        .description("API documentation for the Nexus Human Resources Management System (HRIMS).")
                        .contact(new Contact()
                                .name("HRIMS Team")
                                .email("support@hrnexus.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("http://springdoc.org")));
    }
}
