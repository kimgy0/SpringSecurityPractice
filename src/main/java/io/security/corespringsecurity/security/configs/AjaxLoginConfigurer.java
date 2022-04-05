package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;


public class AjaxLoginConfigurer <H extends HttpSecurityBuilder<H>>
        extends AbstractAuthenticationFilterConfigurer<H,AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {


    //doc -> extends AbstractHttpConfigurer<MyCustomDs1, HttpSecurity>

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private AuthenticationManager authenticationManager;



    public AjaxLoginConfigurer() {
        super(new AjaxLoginProcessingFilter(), null);
        /*
         * 생성자에서는 필터를 생성해서 부모에게 전해준다.
         * 그러면 부모 클래스로부터 필터를 참조할 수 있게 된다.
         */
    }


    /*
     init 과 configure 가 호출된다. 초기화되면서,
     상위 클래스로 가면 최상위 인터페이스를 보여주면서 configure 를 있는 곳 마다 호출한다.
     추상클래스를 다 찾아서 호출

     init 도 있지만 우리가 특별하게 구현한 것은 없어서 냅둔다.
     */
    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) throws Exception {
        // httpSecurity 객체가 넘어오게 된다.
        if(authenticationManager == null){
            authenticationManager = http.getSharedObject(AuthenticationManager.class);
            // httpSecurity 는 sharedObject 라는 공유객체를 저장하고 가져올 수 있는 저장소 개념의 API 를 가지고 있다.
        }
        getAuthenticationFilter().setAuthenticationManager(authenticationManager);
        // 부모클래스에 필터를 전달했기 때문에 가져올 수 있게된다. getAuthenticationFilter()

        getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
        getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);



        // 세션 관련된 설정
        SessionAuthenticationStrategy sessionAuthenticationStrategy =
                http.getSharedObject(SessionAuthenticationStrategy.class);

        if(sessionAuthenticationStrategy != null){
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }



        // RememberMe 관련 설정
        RememberMeServices rememberMeServices =
                http.getSharedObject(RememberMeServices.class);
        if(rememberMeServices != null){
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }





        http.setSharedObject(AjaxLoginProcessingFilter.class, getAuthenticationFilter());
        http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    public AjaxLoginConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler successHandler){
        this.successHandler = successHandler;
        return this;
    }

    public AjaxLoginConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler failureHandler){
        this.failureHandler = failureHandler;
        return this;
    }

    public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        return this;
    }


    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl,"POST");
    }
}
