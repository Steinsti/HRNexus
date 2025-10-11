package com.hrnexus.backend.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.hrnexus.backend.model.Department;

@Repository
public interface DepartmentRepository extends JpaRepository<Department, UUID> {

    /**
     * Finds a Department entity by its name. This is useful when the service
     * layer needs to look up a department based on a unique administrative name
     * (e.g., "Marketing").
     *
     * @param name The name of the department.
     * @return An Optional containing the Department if found.
     */
    Optional<Department> findByDepartmentName(String name);

    /**
     * Checks if a Department with the given name already exists in the
     * database. This is crucial for validation when creating or updating
     * departments to enforce business-level uniqueness.
     *
     * @param name The name of the department.
     * @return true if a department with the name exists, false otherwise.
     */
    boolean existsByDepartmentName(String name);
}
