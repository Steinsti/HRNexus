package com.hrnexus.backend.security.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
    private static final String BEARER_PREFIX = "Bearer ";

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
     * Generates a JWT token for a given UserDetails
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

        return createToken(new HashMap<>(), userDetails.getUsername());
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
     * Validates a JWT token against user details
     *
     * @param token the JWT token to validate
     * @param userDetails the user details to validate against
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        if (!StringUtils.hasText(token) || userDetails == null) {
            return false;
        }

        // Clean token format (remove Bearer prefix if present)
        String cleanToken = cleanTokenFormat(token);

        try {
            String username = getSubjectFromToken(cleanToken);
            return StringUtils.hasText(username)
                    && username.equals(userDetails.getUsername())
                    && !isTokenExpired(cleanToken);
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
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
     * Cleans token format by removing Bearer prefix if present
     *
     * @param token the raw token string
     * @return cleaned token without Bearer prefix
     */
    private String cleanTokenFormat(String token) {
        if (StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {
            return token.substring(BEARER_PREFIX.length()).trim();
        }
        return token;
    }

    /**
     * Checks if the token has expired
     */
    private boolean isTokenExpired(String token) {
        try {
            Date expirationDate = getExpirationDateFromToken(token);
            return expirationDate != null && expirationDate.before(new Date());
        } catch (JwtException e) {
            logger.debug("Error checking token expiration: {}", e.getMessage());
            return true; // Consider expired if we can't determine expiration
        }
    }

    /**
     * Extracts expiration date from token
     */
    private Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Generic method to extract a claim from the token with proper exception
     * handling
     */
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            if (claims == null) {
                throw new IllegalArgumentException("Claims cannot be null");
            }
            return claimsResolver.apply(claims);
        } catch (ExpiredJwtException e) {
            logger.debug("JWT token is expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            logger.debug("JWT token is unsupported: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            logger.debug("JWT token is malformed: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            logger.debug("JWT signature validation failed: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            logger.debug("JWT token compact of handler are invalid: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Extracts all claims from the token with comprehensive exception handling
     */
    private Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
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
