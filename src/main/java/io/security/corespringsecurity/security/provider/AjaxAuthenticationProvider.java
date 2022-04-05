package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

/*
 * Ajax 방식이라고 해서 form 방식과 다른점은 없다.
 */
    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        //authentication -> 인증 전 객체

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();//비밀번호

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
        //구현해줬으니 -> userdetails

        if(!passwordEncoder.matches(password, accountContext.getPassword())) // 일치하지 않는다면
        {
            throw new BadCredentialsException("BadCredentialsException");
        }


        AjaxAuthenticationToken authenticationToken =
                new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        //폼인증
        //생성자 들어가보기. 두번째 생성자 -> 인증되었으니까
        //최종 인증성공 했음

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authenticate) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authenticate);
        //토큰이 이 프로바이더가 인증해야할 토큰이면 인증 처리를 하도록 조건을 준다.
    }
}
