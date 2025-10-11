package com.hrnexus.backend.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hrnexus.backend.exception.DepartmentAlreadyExistsException;
import com.hrnexus.backend.model.Department;
import com.hrnexus.backend.payload.request.DepartmentRequest;
import com.hrnexus.backend.payload.response.DepartmentResponse;
import com.hrnexus.backend.repository.DepartmentRepository;

import lombok.RequiredArgsConstructor;

/**
 * Service layer for handling Departments business logic.
 */
@Service
@RequiredArgsConstructor
public class DepartmentService {

    private final DepartmentRepository departmentRepository;

    /**
     * Creates a new Department, ensuring a department with the same name does
     * not already exist.
     *
     * @param request The DepartmentRequest DTO containing the department name.
     * @return The newly created Department entity.
     * @throws DepartmentAlreadyExistsException if a department with the name
     * already exists.
     */
    @Transactional
    public DepartmentResponse createDepartment(DepartmentRequest request) {
        if (departmentRepository.existsByDepartmentName(request.getDepartmentName())) {
            throw new DepartmentAlreadyExistsException(request.getDepartmentName());
        }

        Department department = Department.builder()
                .departmentName(request.getDepartmentName())
                .departmentCode(request.getDepartmentCode())
                .build();

        department = departmentRepository.save(department);

        return DepartmentResponse.builder()
                .id(department.getId())
                .departmentName(department.getDepartmentName())
                .departmentCode(department.getDepartmentCode())
                .build();
    }

    public List<DepartmentResponse> findAllDepartments() {
        return departmentRepository.findAll()
                .stream()
                .map(department -> DepartmentResponse.builder()
                .id(department.getId())
                .departmentName(department.getDepartmentName())
                .departmentCode(department.getDepartmentCode())
                .build()
                )
                .collect(Collectors.toList());
    }
}
