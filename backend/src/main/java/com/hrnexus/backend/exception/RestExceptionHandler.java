package com.hrnexus.backend.exception;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.data.mapping.PropertyReferenceException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RestExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(RestExceptionHandler.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ISO_OFFSET_DATE_TIME;

    // --- Custom Exception Handlers ---
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(ResourceNotFoundException ex, HttpServletRequest req) {
        return buildAndLog(HttpStatus.NOT_FOUND, ex.getMessage(), req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(ResourceAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleResourceAlreadyExists(ResourceAlreadyExistsException ex, HttpServletRequest req) {
        return buildAndLog(HttpStatus.CONFLICT, ex.getMessage(), req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(IdCardAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleIdCardAlreadyExists(IdCardAlreadyExistsException ex, HttpServletRequest req) {
        return buildAndLog(HttpStatus.CONFLICT, ex.getMessage(), req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(DepartmentAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleDepartmentAlreadyExists(DepartmentAlreadyExistsException ex, HttpServletRequest req) {
        return buildAndLog(HttpStatus.CONFLICT, ex.getMessage(), req.getRequestURI(), false, ex);
    }

    // --- Spring/General Exception Handlers ---
    @ExceptionHandler(PropertyReferenceException.class)
    public ResponseEntity<ErrorResponse> handlePropertyReference(PropertyReferenceException ex, HttpServletRequest req) {
        String msg = "Invalid property in request: " + ex.getPropertyName();
        return buildAndLog(HttpStatus.BAD_REQUEST, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleNotReadable(HttpMessageNotReadableException ex, HttpServletRequest req) {
        String msg;
        Throwable cause = ex.getCause();
        if (cause == null) {
            msg = "Required JSON request body is missing.";
        } else if (cause instanceof InvalidFormatException ife) {
            String fieldPath = ife.getPath().stream()
                    .map(ref -> ref.getFieldName() != null ? ref.getFieldName() : ("[" + ref.getIndex() + "]"))
                    .collect(Collectors.joining("."));
            msg = String.format("Invalid value '%s' for field '%s'. Expected type: %s.",
                    ife.getValue(), fieldPath, ife.getTargetType() != null ? ife.getTargetType().getSimpleName() : "unknown");
        } else if (cause instanceof UnrecognizedPropertyException upe) {
            msg = String.format("Unrecognized field '%s'. Check your field names.", upe.getPropertyName());
        } else {
            String mostSpecificCauseMsg = (ex.getMostSpecificCause() != null) ? ex.getMostSpecificCause().getMessage() : ex.getMessage();
            msg = "Malformed request body: " + mostSpecificCauseMsg;
        }
        return buildAndLog(HttpStatus.BAD_REQUEST, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(InvalidDataAccessApiUsageException.class)
    public ResponseEntity<ErrorResponse> handleInvalidDataAccessApiUsage(InvalidDataAccessApiUsageException ex, HttpServletRequest req) {
        String msg = ex.getMessage() != null && ex.getMessage().contains("id must not be null")
                ? "Missing required relationship ID in request. Please ensure all required IDs are present."
                : "Invalid data access argument provided.";
        return buildAndLog(HttpStatus.BAD_REQUEST, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException ex, HttpServletRequest req) {
        String detailedMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));
        String msg = "Validation failed. Errors: " + detailedMessage;
        return buildAndLog(HttpStatus.BAD_REQUEST, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler({MethodArgumentTypeMismatchException.class, IllegalArgumentException.class})
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception ex, HttpServletRequest req) {
        String msg = ex.getMessage() != null ? ex.getMessage() : "Invalid request";
        return buildAndLog(HttpStatus.BAD_REQUEST, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityViolation(DataIntegrityViolationException ex, HttpServletRequest req) {
        String userFriendlyMessage = "Data conflict: A resource with the provided unique identifier already exists.";
        Throwable rootCause = ex.getRootCause();
        String rootCauseMessage = (rootCause != null) ? rootCause.getMessage() : ex.getMessage();
        if (rootCauseMessage != null) {
            if (rootCauseMessage.contains("duplicate key value violates unique constraint")) {
                try {
                    String detail = rootCauseMessage.substring(rootCauseMessage.indexOf("Detail: Key ("));
                    userFriendlyMessage = detail.replace("Detail: ", "Conflict: ");
                } catch (Exception e) {
                }
            } else if (rootCauseMessage.contains("Duplicate entry")) {
                userFriendlyMessage = "Conflict: " + rootCauseMessage;
            }
        }
        return buildAndLog(HttpStatus.CONFLICT, userFriendlyMessage, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException ex, HttpServletRequest req) {
        String msg = "Authentication failed: invalid username or password.";
        return buildAndLog(HttpStatus.UNAUTHORIZED, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException ex, HttpServletRequest req) {
        String msg = "Access Denied: You do not have the necessary permissions for this resource.";
        return buildAndLog(HttpStatus.FORBIDDEN, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFound(NoResourceFoundException ex, HttpServletRequest req) {
        String msg = "Resource not found: " + ex.getMessage();
        return buildAndLog(HttpStatus.NOT_FOUND, msg, req.getRequestURI(), false, ex);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAll(Exception ex, HttpServletRequest req) {
        return buildAndLog(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected server error occurred. Please contact support.", req.getRequestURI(), true, ex);
    }

    // --- Helper for building and logging error responses ---
    private ResponseEntity<ErrorResponse> buildAndLog(HttpStatus status, String message, String path, boolean isServerError, Exception ex) {
        if (isServerError) {
            log.error("{} for {}: {}", status, path, message, ex);
        } else {
            log.warn("{} for {}: {}", status, path, message);
        }
        ErrorResponse body = new ErrorResponse(
                FMT.format(OffsetDateTime.now()),
                status.value(),
                status.getReasonPhrase(),
                message,
                path
        );
        return ResponseEntity.status(status).body(body);
    }

    // --- Error response DTO ---
    public static class ErrorResponse {

        private final String timestamp;
        private final int status;
        private final String error;
        private final String message;
        private final String path;

        public ErrorResponse(String timestamp, int status, String error, String message, String path) {
            this.timestamp = timestamp;
            this.status = status;
            this.error = error;
            this.message = message;
            this.path = path;
        }

        public String getTimestamp() {
            return timestamp;
        }

        public int getStatus() {
            return status;
        }

        public String getError() {
            return error;
        }

        public String getMessage() {
            return message;
        }

        public String getPath() {
            return path;
        }
    }
}
