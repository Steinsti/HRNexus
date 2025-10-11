package com.hrnexus.backend.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hrnexus.backend.model.Employee;
import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.payload.request.EmployeeUpdateRequest;
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
     * @param request The employee details.
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

    /**
     * Endpoint to retrieve a list of all employees. Accessible only to users
     * with the HR_MANAGER role.
     *
     * @return A ResponseEntity containing a list of all Employee objects.
     */
    @GetMapping
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<List<Employee>> getAllEmployees() {
        List<Employee> employees = employeeService.getAllEmployees();
        return new ResponseEntity<>(employees, HttpStatus.OK);
    }

    /**
     * Endpoint to update an existing employee by their internal ID (Primary
     * Key). Accessible only to users with the HR_MANAGER role.
     *
     * @param id The internal primary key ID of the employee to update.
     * @param request The updated employee details.
     * @return A success message response.
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<MessageResponse> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestBody EmployeeUpdateRequest request) {

        Employee updatedEmployee = employeeService.updateEmployee(id, request);

        return new ResponseEntity<>(
                new MessageResponse("Employee updated successfully. Employee ID: " + updatedEmployee.getEmployeeId()),
                HttpStatus.OK
        );
    }

    /**
     * Endpoint to delete an employee by their internal ID (Primary Key).
     * Accessible only to users with the HR_MANAGER role.
     *
     * @param id The internal primary key ID of the employee to delete.
     * @return A 204 No Content response upon successful deletion.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<Void> deleteEmployee(@PathVariable Long id) {
        employeeService.deleteEmployee(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Endpoint to retrieve a single employee by their ID Card Number.
     * Accessible only to users with the HR_MANAGER role.
     *
     * @param idCardNo The ID card number of the employee.
     * @return A ResponseEntity containing the Employee object.
     */
    @GetMapping("/card/{idCardNo}") // Modified path to prevent conflict with primary ID
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<Employee> getEmployeeByIdCardNo(@PathVariable String idCardNo) {
        Employee employee = employeeService.getEmployeeByIdCardNo(idCardNo);
        return new ResponseEntity<>(employee, HttpStatus.OK);
    }

    /**
     * Endpoint to retrieve a single employee by their internal database ID
     * (Primary Key). Accessible only to users with the HR_MANAGER role.
     *
     * @param id The internal primary key ID of the employee.
     * @return A ResponseEntity containing the Employee object.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<Employee> getEmployeeById(@PathVariable Long id) {
        Employee employee = employeeService.getEmployeeById(id);
        return new ResponseEntity<>(employee, HttpStatus.OK);
    }

}
