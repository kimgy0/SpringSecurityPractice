package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.AccessIp;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {
    AccessIp findByIpAddress(String ipAddress);
}
