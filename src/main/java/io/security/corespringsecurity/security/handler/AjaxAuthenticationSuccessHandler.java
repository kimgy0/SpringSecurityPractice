package io.security.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private ObjectMapper objectMapper = new ObjectMapper();

    //인증 성공 정보를 받을 수 잇음.
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        Account principal = (Account) authentication.getPrincipal();
        /**
         *  AjaxAuthenticationToken authenticationToken =
         *                 new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
         *    프로바이더에서 리턴하기 전에 이미 저장을 해주었음.
         */

        httpServletResponse.setStatus(HttpStatus.OK.value());
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(httpServletResponse.getWriter(), principal);


    }
}
