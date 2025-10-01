package com.hrnexus.backend.exception;

/**
 * Custom exception used to signal a business rule violation when an attempt is
 * made to create a resource (like an Employee) with a unique identifier (ID
 * Card Number) that already exists in the system.
 *
 * This exception is designed to be caught by the GlobalExceptionHandler and
 * mapped to an HTTP 409 Conflict response.
 */
public class IdCardAlreadyExistsException extends RuntimeException {

    /**
     * Constructs a new IdCardAlreadyExistsException with a specific message
     * including the conflicting ID card number.
     *
     * @param idCardNo The ID card number that already exists.
     */
    public IdCardAlreadyExistsException(Long idCardNo) {
        super("An employee with the ID card number " + idCardNo + " already exists.");
    }
}
