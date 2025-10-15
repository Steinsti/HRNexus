package com.hrnexus.backend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hrnexus.backend.enums.Roles;
import com.hrnexus.backend.model.User;
import com.hrnexus.backend.payload.request.LoginRequest;
import com.hrnexus.backend.payload.request.RegisterRequest;
import com.hrnexus.backend.payload.response.JwtResponse;
import com.hrnexus.backend.payload.response.RegisterResponse;
import com.hrnexus.backend.repository.EmployeeRepository;
import com.hrnexus.backend.repository.UserRepository;
import com.hrnexus.backend.security.util.JwtTokenProvider;
import com.hrnexus.backend.service.CustomUserDetailsService;

import jakarta.validation.Valid;

/**
 * REST controller for handling user authentication.
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
     * Authenticates a user and returns a JWT token.
     *
     * @param loginRequest the username and password provided by the user (as
     * form data)
     * @return a ResponseEntity containing the JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @ModelAttribute LoginRequest loginRequest) {
        // Authenticate the user with Spring Security's AuthenticationManager
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        // Load the full UserDetails for token generation
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwt = jwtTokenProvider.generateToken(userDetails);

        // Return the token in a custom response object
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    /**
     * Registers a new employee account.
     *
     * Handles POST /register with a validated request body. Trims the username,
     * rejects existing usernames with 409, and denies non-employee emails with
     * 403. On success, encodes the password, assigns the EMPLOYEE role,
     * persists the user, and returns 201 with a RegisterResponse (id, username,
     * role).
     *
     * @param request validated registration data from the request body
     * @return ResponseEntity with: - 201 Created and RegisterResponse on
     * success - 409 Conflict if the username already exists - 403 Forbidden if
     * registration is not allowed
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
}
