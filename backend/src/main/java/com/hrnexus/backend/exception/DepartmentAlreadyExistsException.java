package com.hrnexus.backend.exception;

/**
 * Custom exception used to signal a business rule violation when an attempt is
 * made to create a department that already exists in the system.
 *
 * This exception is designed to be caught by the GlobalExceptionHandler and
 * mapped to an HTTP 409 Conflict response.
 */
public class DepartmentAlreadyExistsException extends RuntimeException {

    public DepartmentAlreadyExistsException(String departmentName) {
        super("A Department with the name: " + departmentName + " already exists.");
    }
}
