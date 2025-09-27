package com.hrnexus.backend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hrnexus.backend.model.Employee;
import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.payload.response.MessageResponse;
import com.hrnexus.backend.service.EmployeeService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * Controller for managing Employee-related operations. Requires HR_MANAGER role
 * for create operations.
 */
@RestController
@RequestMapping("/api/v1/employees")
@RequiredArgsConstructor
public class EmployeeController {

    private final EmployeeService employeeService;

    /**
     * Endpoint to create a new employee. Accessible only to users with the
     * HR_MANAGER role.
     *
     * * @param request The employee details.
     * @return A success message response.
     */
    @PostMapping("/register")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<MessageResponse> createEmployee(@Valid @RequestBody EmployeeRequest request) {
        Employee newEmployee = employeeService.createEmployee(request);

        return new ResponseEntity<>(
                new MessageResponse("Employee created successfully with ID: " + newEmployee.getEmployeeId()),
                HttpStatus.CREATED
        );
    }

}
