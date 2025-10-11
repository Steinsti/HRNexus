package com.hrnexus.backend.service;

import java.util.List;
import java.util.Locale;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hrnexus.backend.enums.EmploymentStatus;
import com.hrnexus.backend.exception.IdCardAlreadyExistsException;
import com.hrnexus.backend.exception.ResourceNotFoundException;
import com.hrnexus.backend.model.Department;
import com.hrnexus.backend.model.Employee;
import com.hrnexus.backend.model.JobTitle;
import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.repository.DepartmentRepository;
import com.hrnexus.backend.repository.EmployeeRepository;
import com.hrnexus.backend.repository.JobTitleRepository;

import lombok.RequiredArgsConstructor;

/**
 * Implementation of the EmployeeService interface, handling the core business
 * logic and persistence operations.
 */
@Service
@RequiredArgsConstructor
public class EmployeeServiceImpl implements EmployeeService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final JobTitleRepository jobTitleRepository;

    /**
     * Creates and saves a new employee based on the request DTO.
     *
     * @param request The employee data transfer object.
     * @return The saved Employee entity.
     * @throws IdCardAlreadyExistsException if an employee with the given ID
     * card number already exists.
     * @throws ResourceNotFoundException if Department, Job Title, or Manager
     * IDs are invalid.
     */
    @Override
    @Transactional
    public Employee createEmployee(EmployeeRequest request) {

        if (employeeRepository.existsByIdCardNo(request.getIdCardNo())) {
            throw new IdCardAlreadyExistsException(request.getIdCardNo());
        }

        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new ResourceNotFoundException("Department not found with ID: " + request.getDepartmentId()));

        JobTitle jobTitle = jobTitleRepository.findById(request.getJobTitleId())
                .orElseThrow(() -> new ResourceNotFoundException("Job Title not found with ID: " + request.getJobTitleId()));

        Employee manager = null;
        if (request.getManagerId() != null) {
            manager = employeeRepository.findById(request.getManagerId())
                    .orElseThrow(() -> new ResourceNotFoundException("Manager employee not found with ID: " + request.getManagerId()));
        }

        if (request.getEmploymentStatus() == null) {
            throw new ResourceNotFoundException("Employment status must not be null");
        }
        EmploymentStatus status;
        try {
            status = EmploymentStatus.valueOf(request.getEmploymentStatus().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResourceNotFoundException("Invalid employment status: " + request.getEmploymentStatus());
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
                .department(department)
                .jobTitle(jobTitle)
                .manager(manager)
                .hireDate(request.getHireDate())
                .dateOfBirth(request.getDateOfBirth())
                .employmentStatus(status)
                .build();

        return employeeRepository.save(employee);

    }

    /**
     * Retrieves all employees from the database.
     *
     * @return A list of all Employee entities.
     */
    @Override
    public List<Employee> getAllEmployees() {
        return employeeRepository.findAll();
    }

    /**
     * Retrieves a single employee by their ID card number.
     *
     * @param idCardNo The ID card number of the employee to retrieve.
     * @return The Employee entity.
     * @throws ResourceNotFoundException if the employee is not found.
     */
    @Override
    public Employee getEmployeeByIdCardNo(String idCardNo) {
        return employeeRepository.findByIdCardNo(idCardNo)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found with ID card number: " + idCardNo));
    }

    /**
     * Retrieves a single employee by their internal database ID.
     *
     * @param id The primary key ID of the employee.
     * @return The Employee entity.
     * @throws ResourceNotFoundException if the employee is not found.
     */
    @Override
    public Employee getEmployeeById(Long id) {
        return employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found with ID: " + id));
    }
}
