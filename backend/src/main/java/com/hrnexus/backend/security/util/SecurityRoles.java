package com.hrnexus.backend.security.util;

public final class SecurityRoles {

    private SecurityRoles() {
    }

    public static final String HR_OR_ADMIN = "hasAnyRole('HR_MANAGER', 'ADMIN')";
    public static final String ADMIN_ONLY = "hasRole('ADMIN')";
    public static final String HR_ONLY = "hasRole('HR_MANAGER')";
    public static final String EMPLOYEE = "hasAnyRole('EMPLOYEE')";
}
