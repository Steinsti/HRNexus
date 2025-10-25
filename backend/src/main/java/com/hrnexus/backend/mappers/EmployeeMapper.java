package com.hrnexus.backend.mappers;

import org.springframework.stereotype.Component;

import com.hrnexus.backend.enums.EmploymentStatus;
import com.hrnexus.backend.model.Department;
import com.hrnexus.backend.model.Employee;
import com.hrnexus.backend.model.JobTitle;
import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.payload.response.EmployeeResponse;

@Component
public class EmployeeMapper {

    public EmployeeResponse toDto(Employee employee) {
        if (employee == null) {
            return null;
        }

        return EmployeeResponse.builder()
                .id(employee.getId())
                .employeeId(employee.getEmployeeId())
                .firstName(employee.getFirstName())
                .middleName(employee.getMiddleName())
                .lastName(employee.getLastName())
                .email(employee.getEmail())
                .idCardNo(employee.getIdCardNo())
                .phoneNumber(employee.getPhoneNumber())
                .hireDate(employee.getHireDate())
                .dateOfBirth(employee.getDateOfBirth())
                .employmentStatus(employee.getEmploymentStatus())
                .systemUserId(employee.getSystemUserId())
                .department(DepartmentMapper.toDto(employee.getDepartment()))
                .jobTitle(JobTitleMapper.toDto(employee.getJobTitle()))
                .managerId(employee.getManager() != null ? employee.getManager().getId() : null)
                .managerFullName(employee.getManager() != null
                        ? employee.getManager().getFirstName() + " " + employee.getManager().getLastName()
                        : null)
                .build();
    }

    public Employee toEntity(EmployeeRequest request, Department department, JobTitle jobTitle, Employee manager, EmploymentStatus status) {
        return Employee.builder()
                .employeeId(request.getEmployeeId())
                .firstName(request.getFirstName())
                .middleName(request.getMiddleName())
                .lastName(request.getLastName())
                .idCardNo(request.getIdCardNo())
                .email(request.getEmail())
                .phoneNumber(request.getPhoneNumber())
                .department(department)
                .jobTitle(jobTitle)
                .manager(manager)
                .hireDate(request.getHireDate())
                .dateOfBirth(request.getDateOfBirth())
                .employmentStatus(status)
                .build();
    }
}
