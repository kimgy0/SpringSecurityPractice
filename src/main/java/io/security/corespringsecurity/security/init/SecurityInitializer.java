package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.domain.RoleHierarchy;
import io.security.corespringsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
public class SecurityInitializer implements ApplicationRunner {

    //db 로 부터 계층 권한 정보를 가져와서 포맷팅 된 그 결과값을 hierarchy impl 에 전달한다.

    @Autowired
    private RoleHierarchyService roleHierarchyService;
    //포맷팅 된 값 가져옴

    @Autowired
    private RoleHierarchyImpl roleHierarchy;
    //포맷팅 값을 받아야하는 클래스

    @Override
    public void run(ApplicationArguments args) throws Exception {
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        //이 데이터를 impl 에 넘겨준 (RoleHierarchyImpl roleHierarchy; 여기에)
        roleHierarchy.setHierarchy(allHierarchy);
    }
}
