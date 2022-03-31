package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;


    @Override
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

        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = details.getSecretKey();

        if(secretKey == null || !"secret".equals(secretKey)){
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        //폼인증
        //생성자 들어가보기. 두번째 생성자 -> 인증되었으니까
        //최종 인증성공 했음

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authenticate) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authenticate);
        //토큰이 이 프로바이더가 인증해야할 토큰이면 인증 처리를 하도록 조건을 준다.
    }
}
