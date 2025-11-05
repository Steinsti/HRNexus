package com.hrnexus.backend.security.filter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * JWT Request Filter that intercepts HTTP requests to validate JWT tokens and
 * establish security context for authenticated users.
 *
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
    private static final String JWT_COOKIE_NAME = "HRNEXUS-JWT";

    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Constructor-based dependency injection.
     *
     * @param jwtTokenProvider the JWT token provider service
     */
    public JwtRequestFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
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
            // First try to get token from cookie
            String jwt = getCookieValue(request, JWT_COOKIE_NAME)
                    // If no cookie, fall back to Authorization header
                    .orElseGet(() -> extractJwtFromHeader(request));

            if (StringUtils.hasText(jwt) && jwtTokenProvider.validateToken(jwt)) {
                String username = jwtTokenProvider.getUsernameFromToken(jwt);
                List<String> roles = jwtTokenProvider.getClaimFromToken(jwt);

                List<GrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        username, null, authorities);

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            LOGGER.error("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from the Authorization header.
     */
    private String extractJwtFromHeader(HttpServletRequest request) {
        String headerAuth = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith(BEARER_PREFIX)) {
            return headerAuth.substring(BEARER_PREFIX_LENGTH);
        }
        return null;
    }

    private Optional<String> getCookieValue(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }
        return Optional.empty();
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
