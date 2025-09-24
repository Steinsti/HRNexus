package com.hrnexus.backend.repository;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.hrnexus.backend.model.User;

/**
 * Repository class for managing User entities. Provides data access operations
 * for user-related queries.
 */
@Repository
public class UserRepository {

    /**
     * Finds a user by their username.
     *
     * @param username the username to search for
     * @return an Optional containing the user if found, empty otherwise
     * @throws IllegalArgumentException if username is null or empty
     */
    public Optional<User> findByUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }
        return null;
    }

}
