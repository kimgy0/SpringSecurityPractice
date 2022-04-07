package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

@Configuration
@Order(0)
@RequiredArgsConstructor
public class AppConfig {

    private final ResourcesRepository repository;

    @Bean
    public SecurityResourceService securityResourceService(){
        SecurityResourceService securityResourceService = new SecurityResourceService(repository);
        return  securityResourceService;
    }
}
