package it.unikey.springsecuritydemo.PL.mapper.generic;

public interface GenericRestMapper<D, R> {
    R toRest (D dto);
    D toDto (R rest);
}
