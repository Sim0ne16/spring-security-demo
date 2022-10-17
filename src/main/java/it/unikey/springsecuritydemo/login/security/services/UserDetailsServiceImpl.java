package it.unikey.springsecuritydemo.login.security.services;

import it.unikey.springsecuritydemo.DAL.repository.UserRepository;
import it.unikey.springsecuritydemo.login.models.UserSpring;
import it.unikey.springsecuritydemo.login.repository.UserSpringRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

//implementando UserDetailsService ci viene fornito il metodo loadUserByUsername che utilizziamo tramite la repository
//per salvarci l'utente con quell'username e poi buildarlo tramite UserDetailsImpl.
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserSpringRepository userRepository;


    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserSpring user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("user not found: " + username));

        return UserDetailsImpl.build(user);
    }

}
