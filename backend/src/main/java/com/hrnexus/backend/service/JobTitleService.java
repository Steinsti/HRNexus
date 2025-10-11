package com.hrnexus.backend.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hrnexus.backend.exception.ResourceAlreadyExistsException;
import com.hrnexus.backend.model.JobTitle;
import com.hrnexus.backend.payload.request.JobTitleRequest;
import com.hrnexus.backend.payload.response.JobTitleResponse;
import com.hrnexus.backend.repository.JobTitleRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JobTitleService {

    private final JobTitleRepository jobTitleRepository;

    @Transactional
    public JobTitleResponse createJobTitle(JobTitleRequest request) {
        if (jobTitleRepository.existsByTitle(request.getTitle())) {
            throw new ResourceAlreadyExistsException("Job Title", "title", request.getTitle());

        }

        JobTitle jobTitle = JobTitle.builder()
                .title(request.getTitle())
                .description(request.getDescription())
                .build();

        jobTitle = jobTitleRepository.save(jobTitle);

        return JobTitleResponse.builder()
                .id(jobTitle.getId())
                .title(jobTitle.getTitle())
                .description(jobTitle.getDescription())
                .build();
    }

    /**
     * Retrieves all job titles and converts them to response DTOs.
     *
     * @return A list of all JobTitleResponse objects.
     */
    public List<JobTitleResponse> findAllJobTitles() {
        return jobTitleRepository.findAll().stream()
                .map(jobTitle -> JobTitleResponse.builder()
                .id(jobTitle.getId())
                .title(jobTitle.getTitle())
                .description(jobTitle.getDescription())
                .build())
                .collect(Collectors.toList());
    }

}
