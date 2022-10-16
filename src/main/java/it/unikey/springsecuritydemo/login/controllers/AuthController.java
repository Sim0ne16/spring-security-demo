package it.unikey.springsecuritydemo.login.controllers;

import it.unikey.springsecuritydemo.login.models.ERole;
import it.unikey.springsecuritydemo.login.models.RoleSpring;
import it.unikey.springsecuritydemo.login.models.UserSpring;
import it.unikey.springsecuritydemo.login.payload.request.LoginRequest;
import it.unikey.springsecuritydemo.login.payload.request.SignupRequest;
import it.unikey.springsecuritydemo.login.payload.response.MessageResponse;
import it.unikey.springsecuritydemo.login.payload.response.UserInfoResponse;
import it.unikey.springsecuritydemo.login.repository.RoleSpringRepository;
import it.unikey.springsecuritydemo.login.repository.UserSpringRepository;
import it.unikey.springsecuritydemo.login.security.jwt.JwtUtils;
import it.unikey.springsecuritydemo.login.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials = "true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserSpringRepository userSpringRepository;

    @Autowired
    RoleSpringRepository roleSpringRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());

        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                .body(new UserInfoResponse(
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if(userSpringRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("error: username in use"));
        }

        if (userSpringRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        UserSpring userSpring = new UserSpring(signupRequest.getUsername(),
                                                signupRequest.getEmail(),
                                                passwordEncoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<RoleSpring> roleSprings = new HashSet<>();

        if (strRoles == null) {
            RoleSpring userRoleSpring = roleSpringRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: role not found"));
            roleSprings.add(userRoleSpring);

        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        RoleSpring adminRoleSpring = roleSpringRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: role not found"));
                        roleSprings.add(adminRoleSpring);
                        break;
                    case "mod":
                        RoleSpring modRoleSpring = roleSpringRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: role not found"));
                        roleSprings.add(modRoleSpring);
                        break;
                    default:
                        RoleSpring userRoleSpring = roleSpringRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roleSprings.add(userRoleSpring);
                }
            });
        }

        userSpring.setRoles(roleSprings);
        userSpringRepository.save(userSpring);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie responseCookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, responseCookie.toString())
                .body(new MessageResponse("Succesfully logout"));
    }

}
