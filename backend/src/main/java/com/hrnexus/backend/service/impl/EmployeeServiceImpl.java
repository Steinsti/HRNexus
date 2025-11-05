package com.hrnexus.backend.service.impl;

import java.util.Locale;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hrnexus.backend.enums.EmploymentStatus;
import com.hrnexus.backend.exception.IdCardAlreadyExistsException;
import com.hrnexus.backend.exception.ResourceNotFoundException;
import com.hrnexus.backend.mappers.EmployeeMapper;
import com.hrnexus.backend.model.Department;
import com.hrnexus.backend.model.Employee;
import com.hrnexus.backend.model.JobTitle;
import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.payload.response.EmployeeResponse;
import com.hrnexus.backend.repository.DepartmentRepository;
import com.hrnexus.backend.repository.EmployeeRepository;
import com.hrnexus.backend.repository.JobTitleRepository;
import com.hrnexus.backend.service.EmployeeService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class EmployeeServiceImpl implements EmployeeService {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final JobTitleRepository jobTitleRepository;
    private final EmployeeMapper employeeMapper;

    @Override
    public EmployeeResponse createEmployee(EmployeeRequest request) {

        if (request.getHireDate() != null && request.getDateOfBirth() != null) {
            if (request.getHireDate().isBefore(request.getDateOfBirth())) {
                throw new IllegalArgumentException("Hire date must not be before date of birth");
            }
        }

        if (employeeRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists: " + request.getEmail());
        }
        if (employeeRepository.existsByIdCardNo(request.getIdCardNo())) {
            throw new IdCardAlreadyExistsException(request.getIdCardNo());
        }
        if (employeeRepository.existsByEmployeeId(request.getEmployeeId())) {
            throw new IllegalArgumentException("Employee code already exists: " + request.getEmployeeId());
        }

        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new ResourceNotFoundException("Department not found: " + request.getDepartmentId()));
        JobTitle jobTitle = jobTitleRepository.findById(request.getJobTitleId())
                .orElseThrow(() -> new ResourceNotFoundException("JobTitle not found: " + request.getJobTitleId()));

        Employee manager = null;
        if (request.getManagerId() != null) {
            manager = employeeRepository.findById(request.getManagerId())
                    .orElseThrow(() -> new ResourceNotFoundException("Manager not found: " + request.getManagerId()));
        }
        EmploymentStatus status;
        try {
            status = EmploymentStatus.valueOf(request.getEmploymentStatus().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResourceNotFoundException("Invalid employment status: " + request.getEmploymentStatus());
        }

        Employee toSave = employeeMapper.toEntity(request, department, jobTitle, manager, status);
        Employee saved = employeeRepository.save(toSave);

        return employeeMapper.toDto(saved);
    }

    @Override
    public EmployeeResponse updateEmployee(Long id, EmployeeRequest request) {
        Employee existing = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found: " + id));

        // Validate and update fields (only non-null fields in request will be updated)
        if (request.getEmail() != null && !request.getEmail().equals(existing.getEmail())) {
            if (employeeRepository.existsByEmail(request.getEmail())) {
                throw new IllegalArgumentException("Email already exists: " + request.getEmail());
            }
            existing.setEmail(request.getEmail());
        }

        if (request.getPhoneNumber() != null) {
            existing.setPhoneNumber(request.getPhoneNumber());
        }

        if (request.getFirstName() != null) {
            existing.setFirstName(request.getFirstName());
        }
        if (request.getMiddleName() != null) {
            existing.setMiddleName(request.getMiddleName());
        }
        if (request.getLastName() != null) {
            existing.setLastName(request.getLastName());
        }
        if (request.getDateOfBirth() != null) {
            existing.setDateOfBirth(request.getDateOfBirth());
        }
        if (request.getHireDate() != null) {
            existing.setHireDate(request.getHireDate());
        }
        if (request.getEmploymentStatus() != null) {
            try {
                EmploymentStatus status = EmploymentStatus.valueOf(request.getEmploymentStatus().toUpperCase(Locale.ROOT));
                existing.setEmploymentStatus(status);
            } catch (IllegalArgumentException ex) {
                throw new ResourceNotFoundException("Invalid employment status: " + request.getEmploymentStatus());
            }
        }

        // Department change
        if (request.getDepartmentId() != null && !request.getDepartmentId().equals(existing.getDepartment().getId())) {
            Department dept = departmentRepository.findById(request.getDepartmentId())
                    .orElseThrow(() -> new ResourceNotFoundException("Department not found: " + request.getDepartmentId()));
            existing.setDepartment(dept);
        }

        // JobTitle change
        if (request.getJobTitleId() != null && !request.getJobTitleId().equals(existing.getJobTitle().getId())) {
            JobTitle jt = jobTitleRepository.findById(request.getJobTitleId())
                    .orElseThrow(() -> new ResourceNotFoundException("JobTitle not found: " + request.getJobTitleId()));
            existing.setJobTitle(jt);
        }

        // Manager change
        if (request.getManagerId() != null && (existing.getManager() == null || !request.getManagerId().equals(existing.getManager().getId()))) {
            Employee manager = employeeRepository.findById(request.getManagerId())
                    .orElseThrow(() -> new ResourceNotFoundException("Manager not found: " + request.getManagerId()));
            if (manager.getId().equals(existing.getId())) {
                throw new IllegalArgumentException("Employee cannot be their own manager");
            }
            existing.setManager(manager);
        }

        // Additional validations
        if (existing.getHireDate() != null && existing.getDateOfBirth() != null) {
            if (existing.getHireDate().isBefore(existing.getDateOfBirth())) {
                throw new IllegalArgumentException("Hire date must not be before date of birth");
            }
        }

        Employee updated = employeeRepository.save(existing);
        return employeeMapper.toDto(updated);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<EmployeeResponse> getAllEmployees(Pageable pageable) {
        return employeeRepository.findAll(pageable)
                .map(employeeMapper::toDto);
    }

    @Override
    @Transactional(readOnly = true)
    public EmployeeResponse getEmployeeById(Long id) {
        Employee employee = employeeRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Employee with id: " + id + " not found"));
        return employeeMapper.toDto(employee);
    }

    @Override
    @Transactional(readOnly = true)
    public EmployeeResponse getEmployeeByIdCardNo(String idCardNo) {
        Employee employee = employeeRepository.findByIdCardNo(idCardNo)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found with ID Card: " + idCardNo));
        return employeeMapper.toDto(employee);
    }

    @Override
    public void deleteEmployee(Long id) {
        if (!employeeRepository.existsById(id)) {
            throw new ResourceNotFoundException("Employee not found: " + id);
        }
        employeeRepository.deleteById(id);
    }
}
