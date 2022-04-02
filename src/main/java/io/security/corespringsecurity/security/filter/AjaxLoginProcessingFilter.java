package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {


    private ObjectMapper objectMapper = new ObjectMapper();


    public AjaxLoginProcessingFilter() {
        //super(defaultFilterProcessesUrl);
        super(new AntPathRequestMatcher("/api/login"));
        // -> 이정보가 매칭이 되면 이 필터가 로그인을 처리할 수 있도록 필터가 동작한다.
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {

        if(!isAjax(httpServletRequest)){
            throw new IllegalStateException("Authentication is not supported");
        }

        AccountDto accountDto = objectMapper.readValue(httpServletRequest.getReader(), AccountDto.class);
        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("username or password is not empty");
        }

        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
        // getAuthenticationManager() 상위 부모클래스의 메서드.
        // 실질적으로 매니저는 Provider 호출하는데 이 Provider 는 Supported 라는 메서드를 가지고 있는데 이 메서드는 토큰타입이 해당 프로바이더에 맞는 토큰 타입에 대해서만
        // 프로바이더가 인증을 하는데 지금은 우리가 프로바이더를 따로 만들어주지 않아서 인증에 실패한다.
    }

    private boolean isAjax(HttpServletRequest request) {
        // Ajax 인지 아닌지를 판단하게 되는 메서드
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))){
            return true;
        }
        return false;
    }
}
