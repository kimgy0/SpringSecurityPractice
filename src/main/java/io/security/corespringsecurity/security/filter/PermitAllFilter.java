package io.security.corespringsecurity.security.filter;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PermitAllFilter extends FilterSecurityInterceptor {
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;

    /*
     리스트 변수에 저장할건데 타입은 RequestMatcher 에 저장해서 사용자 정보와 matches 를 이용해 맞춰볼 수 있따.
     */
    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();


    public PermitAllFilter(String... permitAllResource) {
        for (String permitRequest : permitAllResource) {
            permitAllRequestMatchers.add(new AntPathRequestMatcher(permitRequest));
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        this.invoke(fi);
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {

        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for (RequestMatcher permitAllRequestMatcher : permitAllRequestMatchers) {
            if(permitAllRequestMatcher.matches(request)){
                permitAll = true;
                break;
            }
        }

        if(permitAll == true){
            return null;
            /* null 이면 인가처리 권한을 심사하지 않는다. */
        }

        return super.beforeInvocation(object);
    }

    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if (fi.getRequest() != null && fi.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null && this.observeOncePerRequest) {
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } else {
            if (fi.getRequest() != null && this.observeOncePerRequest) {
                fi.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }




            //부모를 호출하기 전에 처리해야함.
            InterceptorStatusToken token = beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, (Object)null);
        }

    }
}
