package com.hrnexus.backend.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hrnexus.backend.model.User;
import com.hrnexus.backend.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Fetch user from database using UserRepository
        User user = userRepository.findByUsername(username.trim())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Build UserDetails object from your User entity
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().name()) // Adjust as needed for your roles
                .build();
    }
}
