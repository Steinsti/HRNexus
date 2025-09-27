package com.hrnexus.backend.payload.request;

import java.time.LocalDate;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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

    // Middle name is optional (nullable=true in entity), so validation is omitted
    private String middleName;

    @NotBlank(message = "Last name is required")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotNull(message = "Identity card no is required")
    private Long IdCardNo;

    @NotBlank(message = "Phone number is required")
    private String phoneNumber;

    @NotBlank(message = "Position is required")
    private String position;

    @NotBlank(message = "Department is required")
    private String department;

    @NotNull(message = "Hire date is required")
    private LocalDate hireDate;

    @NotNull(message = "Date of Birth is required")
    private LocalDate dateOfBirth;
}
