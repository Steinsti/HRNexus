package com.hrnexus.backend.controller;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hrnexus.backend.enums.Roles;
import com.hrnexus.backend.model.User;
import com.hrnexus.backend.payload.request.LoginRequest;
import com.hrnexus.backend.payload.request.RegisterRequest;
import com.hrnexus.backend.payload.response.RegisterResponse;
import com.hrnexus.backend.repository.EmployeeRepository;
import com.hrnexus.backend.repository.UserRepository;
import com.hrnexus.backend.security.util.JwtTokenProvider;
import com.hrnexus.backend.service.CustomUserDetailsService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

/**
 * REST controller for handling user authentication and registration. Provides
 * endpoints for user login, registration, checking authentication status, and
 * logout. JWT tokens are managed via HttpOnly, Secure, and SameSite cookies for
 * enhanced security.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final EmployeeRepository employeeRepository;

    /**
     * Constructs an AuthController with necessary dependencies.
     *
     * @param authenticationManager Manages the authentication process in Spring
     * Security.
     * @param jwtTokenProvider Provides utilities for generating and validating
     * JWT tokens.
     * @param customUserDetailsService Provides user-specific data (e.g.,
     * username, password, authorities).
     * @param passwordEncoder Encodes passwords for secure storage.
     * @param userRepository Repository for user data operations.
     * @param employeeRepository Repository for employee data operations (used
     * for registration validation).
     */
    public AuthController(
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            CustomUserDetailsService customUserDetailsService,
            PasswordEncoder passwordEncoder,
            UserRepository userRepository,
            EmployeeRepository employeeRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.customUserDetailsService = customUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.employeeRepository = employeeRepository;
    }

    /**
     * Authenticates a user by their username and password. Upon successful
     * authentication, a JWT token is generated and set as an HttpOnly, Secure,
     * SameSite=Lax cookie in the response header.
     *
     * @param loginRequest The username and password provided by the user
     * (expected as form data via @ModelAttribute).
     * @param response The HttpServletResponse to add the HttpOnly cookie to.
     * @return A ResponseEntity indicating the success of the login operation.
     * Returns 200 OK with a map containing "message" and "tokenSetInCookie"
     * true on success. Returns 401 Unauthorized if authentication fails
     * (handled by Spring Security's exception handling).
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @ModelAttribute LoginRequest loginRequest, HttpServletResponse response) {
        // Authenticate the user with Spring Security's AuthenticationManager
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        // Load the full UserDetails for token generation
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwt = jwtTokenProvider.generateToken(userDetails);
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        ResponseCookie cookie = ResponseCookie.from("HRNEXUS-JWT", jwt)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(jwtTokenProvider.getExpiration())
                .sameSite("Lax")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        // Return the token in a custom response object
        return ResponseEntity.ok(Map.of(
                "message", "Login successful",
                "tokenSetInCookie", true,
                "role", roles
        ));
    }


    /**
     * Registers a new employee account.
     * <p>
     * Handles POST requests to `/register` with a validated request body. It
     * performs the following steps:
     * <ul>
     * <li>Trims the provided username.</li>
     * <li>Checks if the username already exists, returning 409 Conflict if it
     * does.</li>
     * <li>Validates that the provided username (email) corresponds to an
     * existing employee, returning 403 Forbidden if it doesn't.</li>
     * <li>Assigns the {@link Roles#EMPLOYEE} role to the new user.</li>
     * <li>Hashes the password using {@link PasswordEncoder}.</li>
     * <li>Persists the new user in the database.</li>
     * </ul>
     *
     * @param request Validated registration data from the request body.
     * @return ResponseEntity with:
     * <ul>
     * <li>201 Created and {@link RegisterResponse} (id, username, role) on
     * success.</li>
     * <li>409 Conflict if the username already exists.</li>
     * <li>403 Forbidden if registration is not allowed for the given username
     * (email).</li>
     * </ul>
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        String username = request.getUsername().trim();
        if (userRepository.existsByUsername(username)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }

        // Validate that the user is an employee by email 
        boolean isEmployee = employeeRepository.existsByEmail(username);
        if (!isEmployee) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Registration allowed only for employees");
        }

        Roles role = Roles.EMPLOYEE;

        User user = User.builder()
                .username(username)
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .build();

        User saved = userRepository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new RegisterResponse(saved.getId(), saved.getUsername(), saved.getRole()));
    }

    /**
     * Checks the authentication status and returns the user's roles if
     * authenticated. The JWT is stored in the HttpOnly cookie "HRNEXUS-JWT".
     *
     * @param request The HttpServletRequest to retrieve cookies from.
     * @return ResponseEntity with: - 200 OK + { "role": ["ROLE_ADMIN"] } if
     * valid JWT and roles extracted - 200 OK + { "role": [] } if no valid JWT
     * or no roles
     */
    @GetMapping("/status")
    public ResponseEntity<?> checkAuthStatus(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String jwt = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("HRNEXUS-JWT".equals(cookie.getName())) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }

        // If no JWT or invalid
        if (jwt == null || !jwtTokenProvider.validateToken(jwt)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("authenticated", false));
        }

        // Extract roles from the valid JWT
        List<String> roles = jwtTokenProvider.getClaimFromToken(jwt);

        return ResponseEntity.ok(Map.of("authenticated", true, "role", roles));
    }

    /**
     * Logs out the current user by clearing the "HRNEXUS-JWT" HttpOnly cookie.
     * This effectively invalidates the user's session from the browser's
     * perspective.
     *
     * @param response The HttpServletResponse to modify headers and clear the
     * cookie.
     * @return A ResponseEntity indicating the success of the logout operation.
     * Returns 200 OK with a map containing a "message".
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletResponse response) {
        // Create an expired cookie to effectively clear the existing one
        ResponseCookie cookie = ResponseCookie.from("HRNEXUS-JWT", "") // Empty value
                .httpOnly(true)
                .secure(true) // Should be true in production (HTTPS)
                .path("/")
                .maxAge(0) // Set max-age to 0 to expire immediately
                .sameSite("Lax")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
