package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.Account;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    //로그인 실패시 오는 컨트롤러
    @GetMapping(value = {"/login","/api/login"})
    public String loginException(@RequestParam(value = "error",required = false) String error,
                        @RequestParam(value = "exception",required = false) String exception, Model model){

        model.addAttribute("error",error);
        model.addAttribute("exception",exception);

        return "user/login/login";
    }

//    @GetMapping("/login")
//    public String login(){
//        return "user/login/login";
//    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }

        return "redirect:/login";
    }

    @GetMapping(value = {"/denied","/api/denied"})
    public String accessDenied(@RequestParam(value = "exception", required = true) String exception, Model model){


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account principal = (Account) authentication.getPrincipal();

        model.addAttribute("username",principal.getUsername());
        model.addAttribute("exception",exception);

        return "user/login/denied";
    }
}
