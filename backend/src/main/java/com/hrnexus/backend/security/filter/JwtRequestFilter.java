package com.hrnexus.backend.security.filter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hrnexus.backend.security.util.JwtTokenProvider;
import com.hrnexus.backend.service.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * JWT Request Filter that intercepts HTTP requests to validate JWT tokens and
 * establish security context for authenticated users.
 *
 * <p>
 * **Update:** This filter now authenticates users by reading roles directly
 * from the JWT payload, enabling stateless and fast authorization checking.</p>
 *
 * @author HRNexus Development Team
 * @version 1.1
 * @since 1.0
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRequestFilter.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;
    private static final String ROLES_CLAIM = "roles";

    private final JwtTokenProvider jwtTokenProvider;
    // Note: customUserDetailsService is now used only for token validation,
    // if needed (e.g., checking if user is enabled), but not for fetching roles.
    private final CustomUserDetailsService customUserDetailsService;

    /**
     * Constructor-based dependency injection.
     *
     * @param jwtTokenProvider the JWT token provider service
     * @param customUserDetailsService the custom user details service
     */
    public JwtRequestFilter(JwtTokenProvider jwtTokenProvider,
            CustomUserDetailsService customUserDetailsService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.customUserDetailsService = customUserDetailsService;
        LOGGER.info("JwtRequestFilter initialized successfully");
    }

    /**
     * Filters incoming requests to validate JWT tokens and establish security
     * context.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        LOGGER.debug("Processing request: {} {}", request.getMethod(), request.getRequestURI());

        try {
            String jwt = extractJwtFromRequest(request);

            if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                processJwtToken(jwt, request);
            } else if (jwt == null) {
                LOGGER.debug("No JWT token found in request");
            }

        } catch (Exception e) {
            LOGGER.error("Error processing JWT token in request filter. Clearing context.", e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from the Authorization header.
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        final String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith(BEARER_PREFIX)) {
            if (authorizationHeader.length() > BEARER_PREFIX_LENGTH) {
                return authorizationHeader.substring(BEARER_PREFIX_LENGTH).trim();
            } else {
                LOGGER.warn("Authorization header has Bearer prefix but no token");
            }
        }
        return null;
    }

    /**
     * Processes the JWT token and establishes security context if valid.
     *
     * This method now reads authentication data directly from the token claims.
     *
     * * @param jwt the JWT token to process
     * @param request the HTTP servlet request
     */
    private void processJwtToken(String jwt, HttpServletRequest request) {
        Claims claims;
        String username;

        try {
            claims = jwtTokenProvider.getAllClaimsFromToken(jwt);
            username = claims.getSubject();

            LOGGER.debug("Extracted username from JWT: {}", username);

        } catch (JwtException e) {
            LOGGER.warn("Failed to process JWT claims (expired or invalid signature): {}", e.getMessage());
            return; // Exit if token is invalid or expired
        }

        if (!StringUtils.hasText(username)) {
            LOGGER.debug("Username extracted from token is null or empty");
            return;
        }

        // --- Core Change: Read Roles from Claims ---
        @SuppressWarnings("unchecked")
        List<String> roles = claims.get(ROLES_CLAIM, List.class);

        if (roles == null || roles.isEmpty()) {
            LOGGER.warn("No roles found in JWT token for user: {}", username);
            // Even if no roles, we authenticate, but authorization (403) will fail later
            // unless the endpoint is public.
        }

        // Convert string roles to Spring Security GrantedAuthority objects
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.startsWith("ROLE_") ? role : "ROLE_" + role))
                .collect(Collectors.toList());

        // Use the username and authorities from the token to set the context
        setAuthenticationContext(username, authorities, request);
    }

    /**
     * Sets the authentication context in Spring Security.
     *
     * @param username the authenticated username
     * @param authorities the granted authorities (roles)
     * @param request the HTTP servlet request
     */
    private void setAuthenticationContext(String username, List<GrantedAuthority> authorities,
            HttpServletRequest request) {
        try {
            // Create authentication token directly from token claims
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    username, null, authorities); // Username is used as the principal, password is null

            // Set authentication details
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authToken);

            LOGGER.debug("Authentication context set for user: {} with authorities: {}", username, authorities);

        } catch (Exception e) {
            LOGGER.error("Error setting authentication context", e);
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Determines if the filter should be applied to the given request.
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Skip JWT validation for public endpoints
        return path.startsWith("/api/v1/auth/")
                || path.startsWith("/api/public/")
                || path.equals("/health")
                || path.equals("/actuator/health");
    }
}
