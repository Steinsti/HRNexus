package com.hrnexus.backend.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hrnexus.backend.payload.request.DepartmentRequest;
import com.hrnexus.backend.payload.request.JobTitleRequest;
import com.hrnexus.backend.payload.response.DepartmentResponse;
import com.hrnexus.backend.payload.response.JobTitleResponse;
import com.hrnexus.backend.service.DepartmentService;
import com.hrnexus.backend.service.JobTitleService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * Controller for managing administrative setup data such as Departments and Job
 * Titles. Accessible primarily by HR managers.
 */
@RestController
@RequestMapping("/api/v1/admin/data")
@RequiredArgsConstructor
public class AdminDataController {

    private final DepartmentService departmentService;
    private final JobTitleService jobTitleService;

    /**
     * Endpoint to create a new department.
     *
     * @param request The department details.
     * @return The created DepartmentResponse.
     */
    @PostMapping("/departments")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<DepartmentResponse> createDepartment(@Valid @RequestBody DepartmentRequest request) {
        DepartmentResponse response = departmentService.createDepartment(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Endpoint to retrieve a list of all active departments.
     *
     * @return A list of DepartmentResponse objects.
     */
    @GetMapping("/departments")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<List<DepartmentResponse>> listAllDepartments() {
        List<DepartmentResponse> departments = departmentService.findAllDepartments();
        return ResponseEntity.ok(departments);
    }

    /**
     * Endpoint to create a new job title.
     *
     * @param request The job title details.
     * @return The created JobTitleResponse.
     */
    @PostMapping("/jobtitles")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<JobTitleResponse> createJobTitle(@Valid @RequestBody JobTitleRequest request) {
        JobTitleResponse response = jobTitleService.createJobTitle(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Endpoint to retrieve a list of all job titles.
     *
     * @return A list of JobTitleResponse objects.
     */
    @GetMapping("/jobtitles")
    @PreAuthorize("hasRole('HR_MANAGER')")
    public ResponseEntity<List<JobTitleResponse>> listAllJobTitles() {
        List<JobTitleResponse> jobTitles = jobTitleService.findAllJobTitles();
        return ResponseEntity.ok(jobTitles);
    }

}
