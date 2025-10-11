package com.hrnexus.backend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.hrnexus.backend.model.Employee;

/**
 * Repository interface for Employee entity operations.
 */
@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {

    /**
     * Checks if an employee with the given id card no already exists. Spring
     *
     * @param IdCardNo The id card no to check.
     * @return true if an employee exists with this id no, false otherwise.
     */
    boolean existsByIdCardNo(String id);

    /**
     * Checks if an employee with the given email already exists.
     *
     * @param email The email to check.
     * @return true if an employee exists with this email, false otherwise.
     */
    boolean existsByEmail(String email);

     /**
     * Checks if an Employee with the given unique employee ID (e.g., EMP-001) already exists.
     * Useful for enforcing the unique constraint on the natural key.
     * @param employeeId The internal unique employee identifier.
     * @return true if an employee with the ID exists, false otherwise.
     */
    boolean existsByEmployeeId(String employeeId);

    /**
     * Retrieves an employee by their unique ID card number.
     *
     * @param idCardNo The employee's ID card number.
     * @return An Optional containing the Employee entity if found, or an empty
     * Optional otherwise.
     */
    Optional<Employee> findByIdCardNo(String idCardNo);

}
