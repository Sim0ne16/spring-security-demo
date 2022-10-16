package it.unikey.springsecuritydemo.BLL.service.generic;

import it.unikey.springsecuritydemo.BLL.exception.NotFoundException;

public interface GenericCrudService<T> {
    T insert (T dto);
    T getById (Integer id) throws NotFoundException;
}
