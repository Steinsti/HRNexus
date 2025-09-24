package com.hrnexus.backend.security.filter;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hrnexus.backend.security.util.JwtTokenProvider;
import com.hrnexus.backend.service.CustomUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * JWT Request Filter that intercepts HTTP requests to validate JWT tokens and
 * establish security context for authenticated users.
 *
 * <p>
 * This filter processes the Authorization header, extracts JWT tokens,
 * validates them, and sets up Spring Security authentication context.</p>
 *
 * @author HRNexus Development Team
 * @version 1.0
 * @since 1.0
 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    /**
     * Constructor-based dependency injection for better testability and
     * immutability.
     *
     * @param jwtTokenProvider the JWT token provider service
     * @param customUserDetailsService the custom user details service
     */
    public JwtRequestFilter(JwtTokenProvider jwtTokenProvider,
            CustomUserDetailsService customUserDetailsService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.customUserDetailsService = customUserDetailsService;
        logger.info("JwtRequestFilter initialized successfully");
    }

    /**
     * Filters incoming requests to validate JWT tokens and establish security
     * context.
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param filterChain the filter chain
     * @throws ServletException if a servlet error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        logger.debug("Processing request: {} {}", request.getMethod(), request.getRequestURI());

        try {
            // Extract JWT token from Authorization header
            String jwt = extractJwtFromRequest(request);

            if (jwt != null) {
                processJwtToken(jwt, request);
            } else {
                logger.debug("No JWT token found in request");
            }

        } catch (Exception e) {
            logger.error("Error processing JWT token in request filter", e);
            // Clear any partial authentication that might have been set
            SecurityContextHolder.clearContext();
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from the Authorization header.
     *
     * @param request the HTTP servlet request
     * @return the JWT token string, or null if not found or invalid format
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        final String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        if (!StringUtils.hasText(authorizationHeader)) {
            logger.debug("No Authorization header found");
            return null;
        }

        if (!authorizationHeader.startsWith(BEARER_PREFIX)) {
            logger.debug("Authorization header does not start with Bearer prefix");
            return null;
        }

        if (authorizationHeader.length() <= BEARER_PREFIX_LENGTH) {
            logger.warn("Authorization header has Bearer prefix but no token");
            return null;
        }

        return authorizationHeader.substring(BEARER_PREFIX_LENGTH);
    }

    /**
     * Processes the JWT token and establishes security context if valid.
     *
     * @param jwt the JWT token to process
     * @param request the HTTP servlet request
     */
    private void processJwtToken(String jwt, HttpServletRequest request) {
        String username;

        try {
            // Extract username from JWT token
            username = jwtTokenProvider.getSubjectFromToken(jwt);
            logger.debug("Extracted username from JWT: {}", username);

        } catch (Exception e) {
            logger.warn("Failed to extract username from JWT token: {}", e.getMessage());
            return; // Exit early if token is invalid
        }

        // Validate username and check if authentication is not already set
        if (!StringUtils.hasText(username)) {
            logger.debug("Username extracted from token is null or empty");
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            logger.debug("Authentication already exists in security context");
            return;
        }

        // Load user details and validate token
        try {
            UserDetails userDetails = loadUserDetails(username);

            if (userDetails != null && validateTokenWithUserDetails(jwt, userDetails)) {
                setAuthenticationContext(userDetails, request);
                logger.debug("Successfully authenticated user: {}", username);
            } else {
                logger.debug("Token validation failed for user: {}", username);
            }

        } catch (UsernameNotFoundException e) {
            logger.warn("User not found during JWT authentication: {}", username);
        } catch (Exception e) {
            logger.error("Unexpected error during JWT authentication for user: {}", username, e);
        }
    }

    /**
     * Loads user details for the given username.
     *
     * @param username the username to load details for
     * @return UserDetails object or null if loading fails
     */
    private UserDetails loadUserDetails(String username) {
        try {
            return customUserDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            logger.debug("User not found: {}", username);
            throw e; // Re-throw to be handled by caller
        } catch (Exception e) {
            logger.error("Error loading user details for username: {}", username, e);
            return null;
        }
    }

    /**
     * Validates the JWT token against user details.
     *
     * @param jwt the JWT token
     * @param userDetails the user details
     * @return true if token is valid, false otherwise
     */
    private boolean validateTokenWithUserDetails(String jwt, UserDetails userDetails) {
        try {
            return jwtTokenProvider.validateToken(jwt, userDetails);
        } catch (Exception e) {
            logger.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Sets the authentication context in Spring Security.
     *
     * @param userDetails the authenticated user details
     * @param request the HTTP servlet request
     */
    private void setAuthenticationContext(UserDetails userDetails, HttpServletRequest request) {
        try {
            // Create authentication token
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());

            // Set authentication details
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authToken);

            logger.debug("Authentication context set for user: {}", userDetails.getUsername());

        } catch (Exception e) {
            logger.error("Error setting authentication context", e);
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Determines if the filter should be applied to the given request. Override
     * this method to skip filtering for certain paths.
     *
     * @param request the HTTP servlet request
     * @return true if the filter should not be applied, false otherwise
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        // Skip JWT validation for public endpoints
        return path.startsWith("/api/auth/")
                || path.startsWith("/api/public/")
                || path.equals("/health")
                || path.equals("/actuator/health");
    }
}
