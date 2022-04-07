package io.security.corespringsecurity.domain;

import lombok.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "RESOURCES")
@Data
@ToString(exclude = {"roleSet"})
@EntityListeners(value = { AuditingEntityListener.class })
@EqualsAndHashCode(of = "id")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Resources implements Serializable {

    @Id
    @GeneratedValue
    @Column(name = "resource_id")
    private Long id;

    @Column(name = "resource_name")
    private String resourceName;

    @Column(name = "http_method")
    private String httpMethod;

    @Column(name = "order_num")
    private int orderNum;

    @Column(name = "resource_type")
    private String resourceType;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_resources", joinColumns = {
            @JoinColumn(name = "resource_id") }, inverseJoinColumns = { @JoinColumn(name = "role_id") })
    private Set<Role> roleSet = new HashSet<>();
    /*
     * 하나의 자원에 여러개의 권한이 있을 수 있고,
     * 하나의 권한에 여러개의 자원이 있을 수 있기 때문에 다대다 매핑.
     */

}