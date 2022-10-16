package it.unikey.springsecuritydemo.DAL.entity;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity(name = "simple_user")
@Getter
@Setter
@ToString
@RequiredArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false)
    @NotNull
    private String username;

    @Column(nullable = false)
    @NotNull
    private String password;

}
