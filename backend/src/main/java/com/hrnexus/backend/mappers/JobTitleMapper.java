package com.hrnexus.backend.mappers;

import org.springframework.stereotype.Component;

import com.hrnexus.backend.model.JobTitle;
import com.hrnexus.backend.payload.response.JobTitleResponse;

@Component
public class JobTitleMapper {

    public static JobTitleResponse toDto(JobTitle jobTitle) {
        if (jobTitle == null) {
            return null;
        }

        return JobTitleResponse.builder()
                .id(jobTitle.getId())
                .title(jobTitle.getTitle())
                .description(jobTitle.getDescription())
                .build();
    }
}
