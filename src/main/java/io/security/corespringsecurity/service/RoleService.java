package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.Resources;
import io.security.corespringsecurity.domain.Role;

import java.util.List;

public interface RoleService {

    Role getRole(long id);

    List<Role> getRoles();

    void createRole(Role role);

    void deleteRole(long id);
}