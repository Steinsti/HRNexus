package com.hrnexus.backend.payload.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for creating or updating a Department record. Ensures the departmentName
 * field is present and meets size requirements.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DepartmentRequest {

    // Ensure the department name is present (not null, not empty, not whitespace)
    @NotBlank(message = "Department name is mandatory")
    @Size(max = 100, message = "Department name cannot exceed 100 characters")
    private String departmentName;

    @NotBlank(message = "Department code cannot be blank")
    @Size(max = 10, message = "Department code cannot exceed 10 characters")
    private String departmentCode;
}
