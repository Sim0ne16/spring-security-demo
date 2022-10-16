package it.unikey.springsecuritydemo.BLL.dto;

import lombok.Data;

@Data
public class UserDto {
    private Integer id;
    private String username;
    private String password;
}
