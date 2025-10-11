package com.hrnexus.backend.payload.request;

import java.time.LocalDate;
import java.util.UUID;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * DTO for updating an existing Employee. The primary key ID is supplied via the
 * URL path variable.
 */
@Data
public class EmployeeUpdateRequest {

    @NotBlank(message = "First name is required")
    private String firstName;

    private String middleName; // Optional

    @NotBlank(message = "Last name is required")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^[0-9\\-()\\s]*$", message = "Phone number contains invalid characters")
    private String phoneNumber;

    @NotNull(message = "Department ID is required")
    private UUID departmentId;

    @NotNull(message = "Job Title ID is required")
    private Long jobTitleId;

    private Long managerId; // Nullable if the employee reports to no one

    @NotBlank(message = "Employment status is required")
    private String employmentStatus;

    @NotNull(message = "Hire date is required")
    @PastOrPresent(message = "Hire date cannot be in the future")
    private LocalDate hireDate;

    @NotNull(message = "Date of Birth is required")
    private LocalDate dateOfBirth;
}
