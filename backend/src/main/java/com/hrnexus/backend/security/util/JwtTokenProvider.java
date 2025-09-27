package com.hrnexus.backend.security.util;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final int MINIMUM_SECRET_LENGTH = 32; // 256 bits
    private static final long MILLISECONDS_MULTIPLIER = 1000L;
    private static final String ROLES_CLAIM = "roles";

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    /**
     * Validates the JWT secret configuration on startup
     */
    @PostConstruct
    public void validateConfiguration() {
        if (!StringUtils.hasText(secret)) {
            throw new IllegalArgumentException("JWT secret cannot be null or empty");
        }

        // Decode and check the actual key length
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secret);
            if (keyBytes.length < MINIMUM_SECRET_LENGTH) {
                throw new IllegalArgumentException(
                        String.format("JWT secret is too short. Required: %d bytes, Current: %d bytes. "
                                + "Please use a key with at least 256 bits for security.",
                                MINIMUM_SECRET_LENGTH, keyBytes.length));
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("JWT secret must be a valid Base64 encoded string", e);
        }

        if (expiration <= 0) {
            throw new IllegalArgumentException("JWT expiration must be a positive value");
        }

        logger.info("JWT configuration validated successfully. Expiration: {} seconds", expiration);
    }

    /**
     * Generates a JWT token for a given UserDetails, including roles as claims.
     *
     * @param userDetails the user details to generate token for
     * @return JWT token string
     * @throws IllegalArgumentException if userDetails is null or username is
     * empty
     */
    public String generateToken(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("UserDetails cannot be null");
        }
        if (!StringUtils.hasText(userDetails.getUsername())) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        // Extract authorities (roles) and map them to a list of strings
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String, Object> claims = new HashMap<>();
        claims.put(ROLES_CLAIM, roles); // Inject roles into the token payload

        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Creates a JWT token with the specified claims and subject
     */
    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration * MILLISECONDS_MULTIPLIER);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extracts the subject (username) from the token
     *
     * @param token the JWT token
     * @return the username from the token
     * @throws JwtException if token is invalid
     */
    public String getSubjectFromToken(String token) {
        if (!StringUtils.hasText(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        String cleanToken = cleanTokenFormat(token);
        return getClaimFromToken(cleanToken, Claims::getSubject);
    }

    /**
     * Validates a JWT token (signature and expiration)
     *
     * Note: This version only validates the token itself, not against
     * UserDetails. The new JwtRequestFilter will use the claims directly.
     *
     * * @param token the JWT token to validate
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        if (!StringUtils.hasText(token)) {
            return false;
        }

        String cleanToken = cleanTokenFormat(token);

        try {
            // Attempt to parse the claims. If successful, the token is valid (not expired, signature OK)
            getAllClaimsFromToken(cleanToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts all claims from the token with comprehensive exception handling
     */
    public Claims getAllClaimsFromToken(String token) {
        String cleanToken = cleanTokenFormat(token);
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(cleanToken)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            logger.debug("JWT token is expired");
            throw e;
        } catch (UnsupportedJwtException e) {
            logger.debug("JWT token is unsupported");
            throw e;
        } catch (MalformedJwtException e) {
            logger.debug("JWT token is malformed");
            throw e;
        } catch (SignatureException e) {
            logger.debug("JWT signature validation failed");
            throw e;
        } catch (IllegalArgumentException e) {
            logger.debug("JWT token is invalid");
            throw e;
        }
    }

    /**
     * Cleans token format by removing Bearer prefix if present
     */
    private String cleanTokenFormat(String token) {
        final String BEARER_PREFIX = "Bearer ";
        if (StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {
            return token.substring(BEARER_PREFIX.length()).trim();
        }
        return token;
    }

    /**
     * Generic method to extract a claim from the token with proper exception
     * handling
     */
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        // Note: The getSubjectFromToken method should still handle exception propagation
        Claims claims = getAllClaimsFromToken(token);
        if (claims == null) {
            throw new IllegalArgumentException("Claims cannot be null");
        }
        return claimsResolver.apply(claims);
    }

    /**
     * Decodes the secret key for signing with validation
     */
    private SecretKey getSigningKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secret);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            logger.error("Failed to decode JWT secret key", e);
            throw new IllegalStateException("Invalid JWT secret configuration", e);
        }
    }
}
