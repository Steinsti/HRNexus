package com.hrnexus.backend.security;

import java.io.IOException;
import java.io.OutputStream;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hrnexus.backend.payload.response.ErrorResponse;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * Custom AuthenticationEntryPoint used to handle AuthenticationExceptions
 * (e.g., invalid or expired JWT) thrown by the Spring Security filter chain.
 * This ensures a 401 Unauthorized status and a structured JSON body are
 * returned to the client, preventing the generic 403 response with an empty
 * body.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        // Set the response status to 401 Unauthorized
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String errorMessage = authException.getMessage() != null
                ? authException.getMessage()
                : "Authentication failed: Invalid credentials or token.";

        // Create the structured error response DTO, matching the required 4-argument constructor
        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                errorMessage,
                request.getRequestURI() // Path argument
        );

        // Write the custom ErrorResponse JSON to the response body
        OutputStream out = response.getOutputStream();
        objectMapper.writeValue(out, errorResponse);
        out.flush();
    }
}
