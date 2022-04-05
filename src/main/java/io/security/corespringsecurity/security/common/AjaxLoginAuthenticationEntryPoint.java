package io.security.corespringsecurity.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/* 인증에 실패했을 경우 (익명사용자가 접근 권한이 필요한 자원에 접근했을 경우) */
public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        // 인증예외가 넘어오는 파라미터에 집중해보자.
        // 인증을 받지 않고 권한 자원에 접근했기 때문에 401 에러를 던져준다.
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UnAuthorized");
    }
}
