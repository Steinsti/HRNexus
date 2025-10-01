package com.hrnexus.backend.exception;

import java.util.stream.Collectors;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.hrnexus.backend.payload.response.ErrorResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * Global Exception Handler using @ControllerAdvice to manage application-wide
 * exceptions. This ensures consistent and structured error responses (e.g., 404
 * NOT FOUND) with a detailed body.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handles ResourceNotFoundException and returns a 404 NOT FOUND status with
     * a structured ErrorResponse body.
     *
     * @param ex The ResourceNotFoundException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 404
     * status.
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(
            ResourceNotFoundException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.NOT_FOUND;

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage(), // This is the descriptive error message (e.g., "Employee not found...")
                request.getDescription(false).replace("uri=", "") // Extracts the path
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles validation exceptions (e.g., @Valid fails on DTOs) and returns a
     * 400 Bad Request. Aggregates all field errors into a comprehensive
     * message.
     *
     * @param ex The MethodArgumentNotValidException instance.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 400
     * status.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            WebRequest request) { // Added WebRequest to access path information

        HttpStatus status = HttpStatus.BAD_REQUEST;

        // Collect all field errors into a single string message
        String detailedMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        // Re-added the path argument to match the required 4-argument constructor.
        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                "Validation failed. Errors: " + detailedMessage,
                request.getDescription(false).replace("uri=", "") // Path argument
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles Spring Security AccessDeniedException and returns a 403 Forbidden
     * status. This covers authorization failures (user logged in but lacks the
     * required role).
     *
     * @param ex The AccessDeniedException instance.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 403
     * status.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(
            AccessDeniedException ex,
            WebRequest request) { // Added WebRequest to access path information

        HttpStatus status = HttpStatus.FORBIDDEN;

        // Re-added the path argument to match the required 4-argument constructor.
        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                "Access Denied: You do not have the necessary permissions for this resource.",
                request.getDescription(false).replace("uri=", "") // Path argument
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles custom business rule exceptions like duplicate ID card number,
     * mapping them to 409 Conflict.
     *
     * @param ex The IdCardAlreadyExistsException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 409
     * status.
     */
    @ExceptionHandler(IdCardAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleIdCardAlreadyExistsException(
            IdCardAlreadyExistsException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.CONFLICT;
        // Log this at WARN level as it is an expected business validation failure
        log.warn("Business Conflict (409): {}", ex.getMessage());

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                ex.getMessage(),
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles database unique constraint violations
     * (DataIntegrityViolationException) and returns a 409 Conflict status. It
     * attempts to extract a user-friendly message from the root cause.
     *
     * @param ex The DataIntegrityViolationException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 409
     * status.
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityViolation(
            DataIntegrityViolationException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.CONFLICT;
        String userFriendlyMessage = "Data conflict: A resource with the provided unique identifier already exists.";

        String rootCauseMessage = ex.getRootCause() != null ? ex.getRootCause().getMessage() : ex.getMessage();

        if (rootCauseMessage != null) {
            // Attempt to make the message more specific based on the PostgreSQL error format
            // e.g., Detail: Key (email)=(Jake.dalson@example.com) already exists.
            if (rootCauseMessage.contains("duplicate key value violates unique constraint")) {
                try {
                    String detail = rootCauseMessage.substring(rootCauseMessage.indexOf("Detail: Key ("));
                    // Clean up the string to be more client-friendly
                    userFriendlyMessage = detail.replace("Detail: ", "Conflict: ");
                } catch (Exception e) {
                    // Fall back to generic message if parsing fails
                    // Log the root cause here if necessary
                }
            } else if (rootCauseMessage.contains("Duplicate entry")) {
                // Handles MySQL/MariaDB unique constraint message format
                userFriendlyMessage = "Conflict: " + rootCauseMessage;
            }
        }

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                userFriendlyMessage,
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles exceptions where Spring MVC cannot find a resource
     * (controller/endpoint) for the requested URI, typically resulting in a 404
     * Not Found error. This handler ensures unmapped requests return a
     * structured ErrorResponse.
     *
     * @param ex The NoResourceFoundException instance, containing the path that
     * was not found.
     * @param request The current web request context.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 404
     * NOT FOUND status.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFoundException(NoResourceFoundException ex, WebRequest request) {

        HttpStatus status = HttpStatus.NOT_FOUND;

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                "Resource not found: " + ex.getMessage(),
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles all other unhandled exceptions (the catch-all) and returns a 500
     * Internal Server Error status. This is crucial for logging the full stack
     * trace of unexpected errors.
     *
     * @param ex The generic Exception instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 500
     * status.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex, WebRequest request) {

        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        // CRUCIAL: Log the full exception with the stack trace using the two-argument
        // log.error(message, throwable) method. This ensures the full trace is visible 
        // in server logs for debugging purposes.
        log.error("Unhandled Internal Server Error (500): {}", ex.getMessage(), ex);

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                "An unexpected server error occurred. Please contact support.",
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorResponse, status);
    }
}
