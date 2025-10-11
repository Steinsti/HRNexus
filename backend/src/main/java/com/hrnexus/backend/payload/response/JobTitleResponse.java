package com.hrnexus.backend.payload.response;

import lombok.Builder;
import lombok.Data;

/**
 * DTO for sending Job Title data back to the client. Includes the generated ID
 * for reference.
 */
@Data
@Builder
public class JobTitleResponse {

    private Long id;
    private String title;
    private String description;
}
