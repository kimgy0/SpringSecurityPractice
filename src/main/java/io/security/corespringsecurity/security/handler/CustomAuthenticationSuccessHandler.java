package io.security.corespringsecurity.security.handler;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache(); //이전에 사용자 요청에 정보를 담고있는 객체
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy(); // 이동할 수 있게 객체를 만듬.

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        /**
         * 인증 후에 추가적인 작업들을 수행할 수 있을 것이다.
         * 인증 후 객체인 authentication , request , response 등등 을 이용해서 나중에 생각이나면 추가적인 작업을 해보자.
         **/

        //인증에 성공하면 requestCache 를 사용해서 캐시해놓은 페이지로 이동할 것.
        //인증에 성공하지 못하면 로그인 페이지로가고 인증 다시 성공하면 다시가고자 했던 url 정보를 담고있는 requestCache 를 사용해서 여기서 바로 이동할 수 있는 처리를 진행한다.

        //로그인이 성공하기 전에 여러가지 정보를 담고있는 아이들을 세션으로부터 requestCache 정볼르 담아온다.
        SavedRequest savedRequest = requestCache.getRequest(request,response);
        //사용자가 이전에 요청에 대한 정보를 담고있는 객체가 나온다.
        if(savedRequest != null){
            // 사용자가 인증을 시도할 때 없던 요청 url 이나 인증을 하기 이전에 다른 자원에 접근했다가 인증 예외가 발생해서 로그인 페이지로 왔던 경우
            // 이전 정보가 없을 때는 null 이 들어갈 수 있다.
            String target = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request,response,target);
        }else{
            setDefaultTargetUrl("/");
            redirectStrategy.sendRedirect(request,response,getDefaultTargetUrl());
        }
    }
}
