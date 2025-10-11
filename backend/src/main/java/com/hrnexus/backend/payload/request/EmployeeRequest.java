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
 * DTO for creating a new Employee.
 */
@Data
public class EmployeeRequest {

    @NotBlank(message = "Employee ID is required")
    private String employeeId;

    @NotBlank(message = "First name is required")
    private String firstName;

    // Middle name is optional (nullable=true in entity)
    private String middleName;

    @NotBlank(message = "Last name is required")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Identity card no is required")
    private String idCardNo;

    @NotBlank(message = "Phone number is required")
    @Pattern(regexp = "^[0-9\\-()\\s]*$", message = "Phone number contains invalid characters")
    private String phoneNumber;

    @NotNull(message = "Department ID is required")
    private UUID departmentId;

    @NotNull(message = "Job Title ID is required")
    private Long jobTitleId;

    private Long managerId;

    @NotBlank(message = "Employment status is required")
    private String employmentStatus;

    @NotNull(message = "Hire date is required")
    @PastOrPresent(message = "Hire date cannot be in the future")
    private LocalDate hireDate;

    @NotNull(message = "Date of Birth is required")
    private LocalDate dateOfBirth;
}
