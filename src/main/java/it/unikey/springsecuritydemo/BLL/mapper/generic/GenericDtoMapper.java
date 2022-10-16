package it.unikey.springsecuritydemo.BLL.mapper.generic;

public interface GenericDtoMapper<E, D> {
    D toDto (E entity);
    E toEntity (D dto);
}
