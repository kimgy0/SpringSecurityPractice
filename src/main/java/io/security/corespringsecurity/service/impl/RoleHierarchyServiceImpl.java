package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @Override
    public String findAllHierarchy(){
        List<RoleHierarchy> roleHierarchies = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> iterator = roleHierarchies.iterator();

        StringBuilder concatedRoles = new StringBuilder();

        while(iterator.hasNext()){

            RoleHierarchy next = iterator.next();

            if(next.getParentName()!=null){
                concatedRoles.append(next.getParentName().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(next.getChildName());
                concatedRoles.append("\n");
            }
        }
        return concatedRoles.toString();
    }
}
