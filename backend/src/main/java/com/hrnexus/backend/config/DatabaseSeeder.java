package com.hrnexus.backend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import com.hrnexus.backend.enums.Roles;
import com.hrnexus.backend.model.User;
import com.hrnexus.backend.repository.UserRepository;

import lombok.RequiredArgsConstructor;

/**
 * Executes a database seeding task upon application startup to ensure a default
 * administrative user exists.
 */
@Configuration
@RequiredArgsConstructor
public class DatabaseSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // Inject the username from environment variables or application properties.
    // Fallback to "admin@hrnexus.com" if the property 'hrn.admin.username' is not set.
    @Value("${hrn.admin.username:admin@hrnexus.com}")
    private String defaultAdminUsername;

    // Inject the password from environment variables or application properties.
    // Fallback to "password" if the property 'hrn.admin.password' is not set.
    @Value("${hrn.admin.password:password}")
    private String defaultAdminPassword;

    /**
     * This method runs automatically after the Spring context is initialized.
     */
    @Override
    @Transactional
    public void run(String... args) throws Exception {
        if (!userRepository.existsByUsername(defaultAdminUsername)) {

            // 1. Create the default admin user entity
            User adminUser = User.builder()
                    .username(defaultAdminUsername)
                    .password(passwordEncoder.encode(defaultAdminPassword))
                    .role(Roles.ADMIN)
                    .build();

            userRepository.save(adminUser);

            System.out.println("------------------------------------------------------------------------------------");
            System.out.println("DATABASE SEEDER: Default ADMIN user created.");
            System.out.println("Username: " + defaultAdminUsername);
            System.out.println("Password: " + defaultAdminPassword + " (***CHANGE THIS IMMEDIATELY***)");
            System.out.println("------------------------------------------------------------------------------------");
        }
    }
}
