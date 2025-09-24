package com.hrnexus.backend.payload.request;

import com.hrnexus.backend.enums.Roles;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {

    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Size(min = 6, max = 100)
    private String password;

    // Optional: allow client to set a role; default will be EMPLOYEE if null
    private Roles role;
}
