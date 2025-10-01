package com.hrnexus.backend.payload.response;

import java.time.LocalDateTime;

import lombok.Data;

/**
 * DTO for consistent error response structure in the API.
 */
@Data
public class ErrorResponse {

    private final LocalDateTime timestamp;
    private final int status;
    private final String error;
    private final String message;
    private final String path;

    // Constructor used by the exception handler
    public ErrorResponse(int status, String error, String message, String path) {
        this.timestamp = LocalDateTime.now();
        this.status = status;
        this.error = error;
        this.message = message;
        this.path = path;
    }
}
