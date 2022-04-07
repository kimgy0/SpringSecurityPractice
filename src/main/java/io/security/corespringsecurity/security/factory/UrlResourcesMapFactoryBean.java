package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.Setter;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

@Setter
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resource;



    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {
        //여기서 만든 객체가 빈이 된다.
        //즉, map 이 빈이 되도록 반환해야한다.
        if(resource == null){
            //Service 가 매핑된 map 객체를 만들어서 가져오도록 한다.
            init();
        }
        return resource;
    }

    private void init() {
        resource = securityResourceService.getResourceList(); //싱글톤으로 해서 메모리에 하나만 존재하도록 코딩해라.
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
        return FactoryBean.super.isSingleton();
    }
}
