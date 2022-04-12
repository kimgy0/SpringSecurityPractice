package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.domain.AccountDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AopSecurityController {
    @PreAuthorize("hasRole('ROLE_USER') and #account.username == principal.username")
    @GetMapping("/api/preAuthorize")
    public String preAuthorize(AccountDto account, Model model, Principal principal){

        model.addAttribute("method", "Success @PreAuthorize");

        return "aop/method";
    }
}
