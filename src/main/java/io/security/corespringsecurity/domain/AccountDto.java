package io.security.corespringsecurity.domain;

import lombok.Data;

@Data
public class AccountDto {
    private String username;
    private String password;
    private String email;
    private String role;
    private String age;
}
