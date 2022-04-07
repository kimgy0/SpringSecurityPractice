package io.security.corespringsecurity.security.metadatasource;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class UrlFilterInvocationSecurityMetaDataSource implements FilterInvocationSecurityMetadataSource {

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
    //일반 해시맵은 순서를 보장하지 않는다. -> 순서대로 저장할 수 있게끔 생성한다.

    public UrlFilterInvocationSecurityMetaDataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> object) {
        requestMap = object;
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {


        HttpServletRequest request = ((FilterInvocation) o).getRequest();


        //requestMap.put(new AntPathRequestMatcher("/mypage"),
        //       Arrays.asList(new SecurityConfig("ROLE_USER")));
        
        if(requestMap != null){
            Set<Map.Entry<RequestMatcher, List<ConfigAttribute>>> entry = requestMap.entrySet();
            for (Map.Entry<RequestMatcher, List<ConfigAttribute>> requestMatcherListEntry : entry) {
                RequestMatcher matcher = requestMatcherListEntry.getKey();
                if(matcher.matches(request)){
                    // 사용자의 request 로 url 정보가 매칭하는지 봄
                    return requestMatcherListEntry.getValue();
                }
            }
        }

        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet();
        Iterator var2 = this.requestMap.entrySet().iterator();

        while(var2.hasNext()) {
            Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry = (Map.Entry)var2.next();
            allAttributes.addAll((Collection)entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass); // 메서드 or url
    }
}
