package com.hrnexus.backend.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Data Transfer Object for JWT responses. It encapsulates the JWT token to be
 * sent back to the client.
 */
@Data
@AllArgsConstructor
public class JwtResponse {

    private String token;
}
