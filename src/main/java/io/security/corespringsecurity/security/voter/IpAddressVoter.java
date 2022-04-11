package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.Setter;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

@Setter
public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private SecurityResourceService resourceService;


    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object o, Collection<ConfigAttribute> collection) {

        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();


        List<String> accessIpList = resourceService.getAccessIpList();

        int result = ACCESS_DENIED;
        //기본 값

        for (String ip : accessIpList) {
            if(remoteAddress.equals(ip)){
                return ACCESS_ABSTAIN;
            }
        }

        if(result == ACCESS_DENIED){
            throw new AccessDeniedException("Invalid Ip Address Exception");
        }

        return result;
    }
}
