package it.unikey.springsecuritydemo.PL.controller;

import it.unikey.springsecuritydemo.BLL.dto.UserDto;
import it.unikey.springsecuritydemo.BLL.exception.NotFoundException;
import it.unikey.springsecuritydemo.BLL.service.impl.UserDtoServiceImpl;
import it.unikey.springsecuritydemo.PL.mapper.impl.UserRestMapperImpl;
import it.unikey.springsecuritydemo.PL.rest.UserRest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/user_role")
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserRestMapperImpl userRestMapper;
    private final UserDtoServiceImpl userDtoService;

    @GetMapping(path = "/{id}")
    private ResponseEntity<UserRest> getUserById(@PathVariable Integer id){
        try {
            UserDto user = userDtoService.getById(id);
            UserRest userRest = userRestMapper.toRest(user);
            return new ResponseEntity<>(userRest, HttpStatus.OK);
        } catch (NotFoundException e) {
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @PostMapping
    private ResponseEntity<UserRest> postAthlete(@RequestBody UserRest user){
        UserDto userDto = userDtoService.insert(userRestMapper.toDto(user));
        UserRest userRest = userRestMapper.toRest(userDto);
        return new ResponseEntity<>(userRest, HttpStatus.CREATED);
    }
}
