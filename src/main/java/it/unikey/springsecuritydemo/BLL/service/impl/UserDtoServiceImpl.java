package it.unikey.springsecuritydemo.BLL.service.impl;

import it.unikey.springsecuritydemo.BLL.dto.UserDto;
import it.unikey.springsecuritydemo.BLL.exception.NotFoundException;
import it.unikey.springsecuritydemo.BLL.mapper.impl.UserMapperImpl;
import it.unikey.springsecuritydemo.BLL.service.generic.UserDtoService;
import it.unikey.springsecuritydemo.DAL.entity.UserEntity;
import it.unikey.springsecuritydemo.DAL.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDtoServiceImpl implements UserDtoService {

    private final UserRepository userRepository;
    private final UserMapperImpl userMapper;

    @Override
    public UserDto insert(UserDto dto) {
        return userMapper.toDto(userRepository.save(userMapper.toEntity(dto)));
    }

    @Override
    public UserDto getById(Integer id) throws NotFoundException {
        UserEntity userEntity = userRepository.findById(id).orElseThrow(() -> new NotFoundException("not found"));
        return userMapper.toDto(userEntity);
    }
}
