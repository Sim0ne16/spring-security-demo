package it.unikey.springsecuritydemo.PL.rest;

import lombok.Data;

@Data
public class UserRest {
    private Integer id;
    private String username;
    private String password;
}
