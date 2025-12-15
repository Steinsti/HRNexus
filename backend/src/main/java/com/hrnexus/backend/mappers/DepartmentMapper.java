package com.hrnexus.backend.mappers;

import org.springframework.stereotype.Component;

import com.hrnexus.backend.model.Department;
import com.hrnexus.backend.payload.response.DepartmentResponse;

@Component
public class DepartmentMapper {

    public static DepartmentResponse toDto(Department department) {
        if (department == null) {
            return null;
        }

        return DepartmentResponse.builder()
                .id(department.getId())
                .departmentName(department.getDepartmentName())
                .departmentCode(department.getDepartmentCode())
                .build();
    }
}
