package com.hrnexus.backend.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.cdimascio.dotenv.Dotenv;

@Profile("dev")
public class DevDotenvConfig implements EnvironmentPostProcessor {

    private static final Logger logger = LoggerFactory.getLogger(DevDotenvConfig.class);

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        logger.info("######  Loading .env for dev profile ####");
        Dotenv dotenv = Dotenv.configure()
                .ignoreIfMissing()
                .load();
        Map<String, Object> envMap = new HashMap<>();
        dotenv.entries().forEach(entry -> envMap.put(entry.getKey(), entry.getValue()));
        environment.getPropertySources().addFirst(new MapPropertySource("dotenvProperties", envMap));
    }
}
