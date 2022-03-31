package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {


        //여러가지 검증을 하다가 예외를 발생하게 되면 실행하는 곳.
        //아이디가 없거나 패스워드가 일치하지 않거나 할 때 발생하는 예외.

        /**예외를 화면에 표시되도록 처리해봄.**/
        String errorMessage = "Invalid Username or Password";

        if(exception instanceof BadCredentialsException){
            errorMessage = "Invalid Username or Password";

        }else if(exception instanceof InsufficientAuthenticationException){
            //secret key 값이 일치하지 않을 때 -> Provider
            errorMessage = "invalid Secret Key";
        }

        setDefaultFailureUrl("/login?error=true&exception="+exception.getMessage());
        super.onAuthenticationFailure(request, response, exception);
        //부모 클래스에 응답을 위임하기로 한다.

    }
}
