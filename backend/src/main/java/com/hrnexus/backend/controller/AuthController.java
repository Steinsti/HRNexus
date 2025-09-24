package com.hrnexus.backend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
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
import com.hrnexus.backend.repository.UserRepository;
import com.hrnexus.backend.security.util.JwtTokenProvider;
import com.hrnexus.backend.service.CustomUserDetailsService;

import jakarta.validation.Valid;

/**
 * REST controller for handling user authentication.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public AuthController(
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            CustomUserDetailsService customUserDetailsService,
            PasswordEncoder passwordEncoder,
            UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.customUserDetailsService = customUserDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    /**
     * Authenticates a user and returns a JWT token.
     *
     * @param loginRequest the username and password provided by the user
     * @return a ResponseEntity containing the JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        // Authenticate the user with Spring Security's AuthenticationManager
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));

        // Load the full UserDetails for token generation
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(loginRequest.getUsername());

        // Generate the JWT token
        String jwt = jwtTokenProvider.generateToken(userDetails);

        // Return the token in a custom response object
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        String username = request.getUsername().trim();
        if (userRepository.existsByUsername(username)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }

        Roles role = request.getRole() != null ? request.getRole() : Roles.EMPLOYEE;

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
