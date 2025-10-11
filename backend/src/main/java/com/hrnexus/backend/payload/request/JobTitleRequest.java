package com.hrnexus.backend.payload.request;
import jakarta.validation.constraints.NotBlank;

import lombok.Data;

/**
 * DTO for creating a new Job Title.
 */
@Data
public class JobTitleRequest {

    @NotBlank(message = "Job title is required")
    private String title;

    private String description;
}
