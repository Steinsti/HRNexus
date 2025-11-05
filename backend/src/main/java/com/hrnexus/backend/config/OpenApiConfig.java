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
 * OpenAPI (Swagger) configuration for HR Nexus Backend.
 *
 * <p>
 * This configuration documents the authentication mechanism as an OAuth2
 * Password Grant flow. However, the backend issues a JWT via a secure, HttpOnly
 * cookie instead of a standard Bearer token header.
 * </p>
 *
 * <p>
 * Swagger clients can still use the password flow for testing purposes, but
 * real frontend clients (React app) will rely on cookie-based session
 * authentication with CORS and credentials enabled.
 * </p>
 */
@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME_NAME = "OAuth2 - Cookie-Based JWT";
    private static final String TOKEN_URL = "/api/v1/auth/login";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                // Attach security requirement globally
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME_NAME))
                .components(new Components()
                        // Define OAuth2 password grant scheme
                        .addSecuritySchemes(SECURITY_SCHEME_NAME, new SecurityScheme()
                                .name(SECURITY_SCHEME_NAME)
                                .type(SecurityScheme.Type.OAUTH2)
                                .description("""
                                        Authenticate using your username and password.
                                        A JWT will be issued and stored in a secure, HttpOnly cookie
                                        named 'jwt' for subsequent authenticated requests.
                                        """)
                                .flows(new OAuthFlows()
                                        .password(new OAuthFlow()
                                                .tokenUrl(TOKEN_URL)
                                                .scopes(new Scopes()
                                                        .addString("read", "Access read operations")
                                                        .addString("write", "Access write operations")
                                                )
                                        )
                                )
                        )
                )
                .info(new Info()
                        .title("HR Nexus Backend API")
                        .version("1.0.0")
                        .description("""
                                API documentation for the HR Nexus Human Resources Management System (HRIMS).
                                Authentication uses cookie-based JWT for security, but follows OAuth2 Password flow semantics
                                for integration and testing purposes in Swagger UI.
                                """)
                        .contact(new Contact()
                                .name("HRIMS Team")
                                .email("support@hrnexus.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("http://springdoc.org")));
    }
}
