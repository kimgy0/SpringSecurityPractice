package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

public class SecurityResourceService {

    // 자원을 가져와서 권한과 자원이 매핑된 map 을 만들어야한다.
    private ResourcesRepository resourceRepository;

    public SecurityResourceService(ResourcesRepository repository) {
        resourceRepository = repository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        LinkedHashMap<RequestMatcher,List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourceRepository.findAllResources();

        resourcesList.forEach(resource -> {

            List<ConfigAttribute> configAttributeList = new ArrayList<>();

            resource.getRoleSet().forEach(role -> {
                configAttributeList.add(new SecurityConfig(role.getRoleName()));
                result.put(new AntPathRequestMatcher(resource.getResourceName()),configAttributeList);
            });
        });
        return result;
    }
}
