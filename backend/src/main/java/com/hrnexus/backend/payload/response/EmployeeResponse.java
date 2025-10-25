package com.hrnexus.backend.payload.response;

import java.time.LocalDate;

import com.hrnexus.backend.enums.EmploymentStatus;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmployeeResponse {

    private Long id;
    private String employeeId;
    private String firstName;
    private String middleName;
    private String lastName;
    private String idCardNo;
    private String email;
    private String phoneNumber;
    private LocalDate hireDate;
    private LocalDate dateOfBirth;
    private EmploymentStatus employmentStatus;
    private String systemUserId;

    private DepartmentResponse department;
    private JobTitleResponse jobTitle;

    private Long managerId;
    private String managerFullName;
}
