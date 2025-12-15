package com.hrnexus.backend.payload.response;

import java.util.UUID;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for sending Department details (ID, Name and department code) to the
 * client.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DepartmentResponse {

    private UUID id;

    private String departmentCode;

    private String departmentName;
}
