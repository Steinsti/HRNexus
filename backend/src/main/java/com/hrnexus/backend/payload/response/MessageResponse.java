package com.hrnexus.backend.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Generic response DTO for sending simple messages back to the client.
 */
@Data
@AllArgsConstructor
public class MessageResponse {

    private String message;
}
