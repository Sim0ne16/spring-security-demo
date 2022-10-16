package it.unikey.springsecuritydemo.PL.mapper.impl;

import it.unikey.springsecuritydemo.BLL.dto.UserDto;
import it.unikey.springsecuritydemo.PL.mapper.generic.GenericRestMapper;
import it.unikey.springsecuritydemo.PL.rest.UserRest;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserRestMapperImpl extends GenericRestMapper<UserDto, UserRest> {
}
