package com.hrnexus.backend.controller;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
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

import com.hrnexus.backend.payload.request.EmployeeRequest;
import com.hrnexus.backend.payload.response.EmployeeResponse;
import static com.hrnexus.backend.security.util.SecurityRoles.HR_OR_ADMIN;
import com.hrnexus.backend.service.EmployeeService;
import com.hrnexus.backend.service.impl.EmployeeServiceImpl;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeController {

    private final EmployeeServiceImpl employeeServiceImpl;


    private final EmployeeService employeeService;


    public EmployeeController(EmployeeService employeeService, EmployeeServiceImpl employeeServiceImpl) {
        this.employeeService = employeeService;
        this.employeeServiceImpl = employeeServiceImpl;
    }


    /**
* Retrieves a list of all employees. Accessible only by users with
     * HR_MANAGER or ADMIN roles.
     *
* @return ResponseEntity containing a list of EmployeeResponse.
     */
    @GetMapping
    @PreAuthorize(HR_OR_ADMIN)
    public ResponseEntity<Page<EmployeeResponse>> getAllEmployees(@PageableDefault(size = 20) Pageable pageable) {
        return ResponseEntity.ok(employeeServiceImpl.getAllEmployees(pageable));
    }


    /**
* Retrieves a specific employee by ID. Accessible only by HR_MANAGER or
     * ADMIN.
     *
* @param id UUID of the employee
     * @return EmployeeResponse if found
     */
    @GetMapping("/{id}")
    @PreAuthorize(HR_OR_ADMIN)
    public ResponseEntity<EmployeeResponse> getEmployeeById(@PathVariable Long id) {
        return ResponseEntity.ok(employeeService.getEmployeeById(id));
    }


    /**
* Creates a new employee record. Accessible only by HR_MANAGER or ADMIN.
     *
* @param request validated employee create request data
     * @return the created employee data
     */
    @PostMapping
    @PreAuthorize(HR_OR_ADMIN)
    public ResponseEntity<EmployeeResponse> createEmployee(@Valid @RequestBody EmployeeRequest request) {
        return ResponseEntity.ok(employeeService.createEmployee(request));
    }


    /**
* Updates an existing employee.
     *
* @param id employee ID
     * @param request updated data
     * @return updated employee response
     */
    @PutMapping("/{id}")
    @PreAuthorize(HR_OR_ADMIN)
    public ResponseEntity<EmployeeResponse> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestBody EmployeeRequest request) {
        return ResponseEntity.ok(employeeServiceImpl.updateEmployee(id, request));
    }


    /**
* Deletes an employee by ID.
     *
* @param id employee ID
     * @return deletion confirmation
     */
    @DeleteMapping("/{id}")
    @PreAuthorize(HR_OR_ADMIN)
    public ResponseEntity<String> deleteEmployee(@PathVariable Long id) {
        // perform deletion via service (use the appropriate service implementation)
        employeeServiceImpl.deleteEmployee(id);
        return ResponseEntity.ok("Employee deleted successfully");
    }
}
