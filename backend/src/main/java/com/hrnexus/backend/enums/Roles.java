package com.hrnexus.backend.enums;

/**
 * Enum representing different user roles in the HR Nexus system. This enum is
 * persisted as STRING values in the database.
 */
public enum Roles {
    /**
     * Administrator role with full system access
     */
    ADMIN,
    /**
     * HR Manager role with HR-specific permissions
     */
    HR_MANAGER,
    /**
     * Employee role with basic user permissions
     */
    EMPLOYEE,
    /**
     * Manager role with team management permissions
     */
    MANAGER
}
