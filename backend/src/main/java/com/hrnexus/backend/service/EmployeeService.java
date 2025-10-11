package com.hrnexus.backend.service;

import java.util.List;

import com.hrnexus.backend.model.Employee;
import com.hrnexus.backend.payload.request.EmployeeRequest;

/**
 * Interface defining the contract for Employee business logic operations. This
 * separation ensures decoupling and simplifies testing.
 */
public interface EmployeeService {

    /**
     * Creates and saves a new employee based on the request DTO.
     *
     * @param request The employee data transfer object.
     * @return The saved Employee entity.
     */
    Employee createEmployee(EmployeeRequest request);

    /**
     * Retrieves all employees from the database.
     *
     * @return A list of all Employee entities.
     */
    List<Employee> getAllEmployees();

    /**
     * Retrieves a single employee by their ID card number.
     *
     * @param idCardNo The ID card number of the employee to retrieve.
     * @return The Employee entity.
     */
    Employee getEmployeeByIdCardNo(String idCardNo);

    /**
     * Retrieves a single employee by their internal database ID.
     *
     * @param id The primary key ID of the employee.
     * @return The Employee entity.
     */
    Employee getEmployeeById(Long id);
}
