package com.hrnexus.backend.payload.response;

import com.hrnexus.backend.enums.Roles;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegisterResponse {
    private Integer id;
    private String username;
    private Roles role;
}
