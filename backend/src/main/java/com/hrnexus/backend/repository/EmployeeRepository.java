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
    boolean existsByIdCardNo(Long id);

    /**
     * Retrieves an employee by their unique ID card number.
     *
     * @param idCardNo The employee's ID card number.
     * @return An Optional containing the Employee entity if found, or an empty
     * Optional otherwise.
     */
    Optional<Employee> findByIdCardNo(Long idCardNo);

}
