package com.hrnexus.backend.model;

import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entity representing a department within the organization, including its
 * unique code and name.
 */
@Entity
@Table(name = "departments")
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class Department {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String departmentCode;

    @Column(nullable = false, unique = true)
    private String departmentName;

}
