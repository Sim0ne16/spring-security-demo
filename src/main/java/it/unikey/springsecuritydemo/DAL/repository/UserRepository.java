package it.unikey.springsecuritydemo.DAL.repository;

import it.unikey.springsecuritydemo.DAL.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {
}
