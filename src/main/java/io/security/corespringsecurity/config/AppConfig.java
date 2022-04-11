package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.listener.SetupDataLoader;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Configuration
@Order(0)
@RequiredArgsConstructor
public class AppConfig {

    private final ResourcesRepository repository;
    private final AccessIpRepository ipRepository;

    @Bean
    public SecurityResourceService securityResourceService(){
        SecurityResourceService securityResourceService = new SecurityResourceService(repository, ipRepository);
        return  securityResourceService;
    }

    @Bean
    public SetupDataLoader setupDataLoader(){
        return new SetupDataLoader();
    }
}
