package com.hrnexus.backend.exception;

import java.util.stream.Collectors;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.hrnexus.backend.payload.response.ErrorResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * Global Exception Handler using @ControllerAdvice to manage application-wide
 * exceptions. This ensures consistent and structured error responses.
 */
@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handles request body deserialization exceptions (JSON parsing errors or
     * missing body) and returns a 400 Bad Request, preventing the leak of
     * internal Java details.
     *
     * @param ex The HttpMessageNotReadableException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 400
     * status.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException(
            HttpMessageNotReadableException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.BAD_REQUEST;
        String userFriendlyMessage;
        String detailedMessage;

        Throwable cause = ex.getCause();

        if (cause == null) {
            // Required request body is missing (empty payload)
            userFriendlyMessage = "Required JSON request body is missing.";
            detailedMessage = "The request payload was empty. Please ensure a valid JSON body is sent.";
        } else if (cause instanceof InvalidFormatException ife) {
            // Data type mismatch
            String fieldPath = ife.getPath().stream()
                    .map(ref -> ref.getFieldName() != null ? ref.getFieldName() : ("[" + ref.getIndex() + "]"))
                    .collect(Collectors.joining("."));

            detailedMessage = String.format(
                    "Invalid value '%s' provided for field '%s'. Expected type was '%s'.",
                    ife.getValue(),
                    fieldPath,
                    ife.getTargetType() != null ? ife.getTargetType().getSimpleName() : "unknown"
            );
            userFriendlyMessage = "Data Type Mismatch in Request Body";
        } else if (cause instanceof UnrecognizedPropertyException upe) {
            // Unknown field
            detailedMessage = String.format(
                    "Unrecognized field '%s'. Check your field names.",
                    upe.getPropertyName()
            );
            userFriendlyMessage = "Unknown Field in Request Body";
        } else {
            // Other general parsing failure (e.g., malformed syntax)
            userFriendlyMessage = "The request body is invalid or malformed.";
            // Use a generic, safe message instead of ex.getMessage() to prevent leaks
            detailedMessage = "General JSON syntax or format error. Check for malformed JSON structure.";
            log.error("JSON Deserialization Failure: {}", ex.getMessage());
        }

        log.warn("Bad Request (400) - Deserialization Error: {}", detailedMessage);

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                userFriendlyMessage + ": " + detailedMessage,
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles Data Access exceptions thrown when a required foreign key ID is
     * null. Returns a 400 Bad Request.
     *
     * @param ex The InvalidDataAccessApiUsageException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 400
     * status.
     */
    @ExceptionHandler(InvalidDataAccessApiUsageException.class)
    public ResponseEntity<ErrorResponse> handleInvalidDataAccessApiUsageException(
            InvalidDataAccessApiUsageException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.BAD_REQUEST;
        String message = ex.getMessage() != null && ex.getMessage().contains("id must not be null")
                ? "Missing required relationship ID in request. A foreign key (e.g., Department ID, Job Title ID) was null. Please ensure all required IDs are present."
                : "Invalid data access argument provided.";

        log.warn("Bad Request (400) - Missing Required ID: {}", message, ex);

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                message,
                request.getDescription(false).replace("uri=", "")
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles ResourceNotFoundException and returns a 404 NOT FOUND status.
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
                ex.getMessage(), // This is the descriptive error message
                request.getDescription(false).replace("uri=", "") // Extracts the path
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles validation exceptions (@Valid fails on DTOs) and returns a 400
     * Bad Request. Aggregates all field errors into a single message.
     *
     * @param ex The MethodArgumentNotValidException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 400
     * status.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.BAD_REQUEST;

        // Collect all field errors into a single string message
        String detailedMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

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
     * status.
     *
     * @param ex The AccessDeniedException instance.
     * @param request The current web request.
     * @return A ResponseEntity containing the custom ErrorResponse and HTTP 403
     * status.
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(
            AccessDeniedException ex,
            WebRequest request) {

        HttpStatus status = HttpStatus.FORBIDDEN;

        ErrorResponse errorResponse = new ErrorResponse(
                status.value(),
                status.getReasonPhrase(),
                "Access Denied: You do not have the necessary permissions for this resource.",
                request.getDescription(false).replace("uri=", "") // Path argument
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    /**
     * Handles custom business rule exceptions (e.g.,
     * IdCardAlreadyExistsException),
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
     * (DataIntegrityViolationException) and returns a 409 Conflict status with
     * a user-friendly message.
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
            if (rootCauseMessage.contains("duplicate key value violates unique constraint")) {
                try {
                    String detail = rootCauseMessage.substring(rootCauseMessage.indexOf("Detail: Key ("));
                    // Clean up the string to be more client-friendly
                    userFriendlyMessage = detail.replace("Detail: ", "Conflict: ");
                } catch (Exception e) {
                    // Fall back to generic message if parsing fails
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
     * Handles exceptions where Spring MVC cannot find an endpoint for the
     * requested URI, returning a structured 404 Not Found error.
     *
     * @param ex The NoResourceFoundException instance.
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
     * Internal Server Error status. Crucial for logging the full stack trace.
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
        // log.error(message, throwable) method.
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
