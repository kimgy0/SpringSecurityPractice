package io.security.corespringsecurity;

import io.security.corespringsecurity.security.listener.SetupDataLoader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
public class CoreSpringSecurityApplication {

    public static void main(String[] args) {
//        SpringApplication app = new SpringApplication( CoreSpringSecurityApplication.class);
//        app.addListeners( new SetupDataLoader());
//        app.run(args);
        SpringApplication.run(CoreSpringSecurityApplication.class, args);
    }

}
