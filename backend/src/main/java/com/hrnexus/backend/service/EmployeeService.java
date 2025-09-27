package com.hrnexus.backend.service;

import com.hrnexus.backend.model.Employee;
import org.springframework.stereotype.Service;
import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.repository.EmployeeRepository;
import lombok.RequiredArgsConstructor;

/**
 * Service layer for handling Employee business logic.
 */
@Service
@RequiredArgsConstructor
public class EmployeeService {

    private final EmployeeRepository employeeRepository;

    /**
     * Creates and saves a new employee based on the request DTO.
     *
     * @param request The employee data transfer object.
     * @return The saved Employee entity.
     * @throws RuntimeException if an employee with the given email already
     * exists.
     */
    public Employee createEmployee(EmployeeRequest request) {
        // Check if employee with this Id no already exists
        if (employeeRepository.existsByIdCardNo(request.getIdCardNo())) {
            throw new RuntimeException("An employee with the id no " + request.getIdCardNo() + " already exists."
            );
        }

        // Convert request DTO to Employee entity
        Employee employee = Employee.builder()
                .employeeId(request.getEmployeeId())
                .firstName(request.getFirstName())
                .middleName(request.getMiddleName())
                .lastName(request.getLastName())
                .idCardNo(request.getIdCardNo())
                .email(request.getEmail())
                .phoneNumber(request.getPhoneNumber())
                .position(request.getPosition())
                .department(request.getDepartment())
                .hireDate(request.getHireDate())
                .dateOfBirth(request.getDateOfBirth())
                .build();

        return employeeRepository.save(employee);

    }
}
