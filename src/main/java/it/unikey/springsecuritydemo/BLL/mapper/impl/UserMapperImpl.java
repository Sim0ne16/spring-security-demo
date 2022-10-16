package it.unikey.springsecuritydemo.BLL.mapper.impl;

import it.unikey.springsecuritydemo.BLL.dto.UserDto;
import it.unikey.springsecuritydemo.BLL.mapper.generic.GenericDtoMapper;
import it.unikey.springsecuritydemo.DAL.entity.UserEntity;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapperImpl extends GenericDtoMapper<UserEntity, UserDto> {

}
