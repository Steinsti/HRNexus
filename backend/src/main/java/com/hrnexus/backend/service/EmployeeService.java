package com.hrnexus.backend.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.payload.response.EmployeeResponse;

public interface EmployeeService {

    /**
     * Creates a new employee.
     *
     * @param request DTO carrying employee registration data
     * @return EmployeeResponseDTO
     */
    EmployeeResponse createEmployee(EmployeeRequest request);

    /**
     * Updates an existing employee by ID.
     *
     * @param id employee DB ID
     * @param request DTO carrying updated employee info
     * @return updated EmployeeResponse
     */
    EmployeeResponse updateEmployee(Long id, EmployeeRequest request);

    /**
     * Retrieves paginated employees list.
     *
     * @param pageable page number + size + sort
     * @return Page of EmployeeResponse
     */
    Page<EmployeeResponse> getAllEmployees(Pageable pageable);

    /**
     * Retrieves an employee by internal ID.
     */
    EmployeeResponse getEmployeeById(Long id);

    /**
     * Retrieves an employee by ID card number.
     */
    EmployeeResponse getEmployeeByIdCardNo(String idCardNo);

    /**
     * Deletes an employee.
     */
    void deleteEmployee(Long id);
}
