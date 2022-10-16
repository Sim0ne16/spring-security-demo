package it.unikey.springsecuritydemo.login.repository;

import it.unikey.springsecuritydemo.login.models.ERole;
import it.unikey.springsecuritydemo.login.models.RoleSpring;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleSpringRepository  extends JpaRepository<RoleSpring, Long> {

    Optional<RoleSpring> findByName(ERole name);
}
