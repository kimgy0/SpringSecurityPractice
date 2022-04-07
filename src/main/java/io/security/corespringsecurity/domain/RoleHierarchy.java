package io.security.corespringsecurity.domain;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import java.io.Serializable;
import java.lang.annotation.Target;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "ROLE_HIERARCHY")
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@ToString(exclude = {"parentName", "roleHierarchy"})
public class RoleHierarchy implements Serializable {
    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "child_name")
    private String childName; //Role 이름

    @ManyToOne(cascade = {CascadeType.ALL},fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_name", referencedColumnName = "child_name")
    private RoleHierarchy parentName; //childName 이 가지고 있는 부모이름.

    @OneToMany(mappedBy = "parentName", cascade = {CascadeType.ALL})
    private Set<RoleHierarchy> roleHierarchy = new HashSet<RoleHierarchy>();
}
