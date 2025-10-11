package com.hrnexus.backend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.hrnexus.backend.model.JobTitle;

@Repository
public interface JobTitleRepository extends JpaRepository<JobTitle, Long> {

    /**
     * Finds a JobTitle entity by its unique title string. This is useful for
     * looking up a job based on its name (e.g., "Software Engineer").
     *
     * @param title The official title of the job.
     * @return An Optional containing the JobTitle if found.
     */
    Optional<JobTitle> findByTitle(String title);

    /**
     * Checks if a JobTitle with the given title already exists in the database.
     * This is vital for enforcing uniqueness when creating new job titles.
     *
     * @param title The title of the job.
     * @return true if a job title with the given name exists, false otherwise.
     */
    boolean existsByTitle(String title);

}
