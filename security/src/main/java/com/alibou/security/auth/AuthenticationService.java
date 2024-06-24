package com.alibou.security.auth;

import com.alibou.security.config.JwtService;
import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor    // automatically inject dependencies of object using final in field declaration
public class AuthenticationService {
    // inject dependency of UserRepository to interact with database
    private final UserRepository repository;
    // inject dependency of PasswordEncoder so that we could save the encoded password in db
    private final PasswordEncoder passwordEncoder;
    // inject dependency of JwtService to generate jwtToken from user data
    private final JwtService jwtService;
    // inject dependency of AuthenticationManager to authenticate user based on username(email in this project) and password
    private final AuthenticationManager authenticationManager;
    // method to register a user(business functinality)
    public AuthenticationResponse register(RegisterRequest request){
        // create user object from request object provided by client
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        repository.save(user);  // save the user data in database

        // generate jwtToken from user data
        var jwtToken = jwtService.generateToken(user);

        // return the AuthenticationResponse object which contains the jwtToken
        return AuthenticationResponse.builder()
                .token(jwtToken)    // pass the jwtToken in AuthenticationResponse and return it
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // authenticate user with authenticationManager
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // get the user by email field from database
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(
                        () -> new UsernameNotFoundException("User with the given email not found : " + request.getEmail()));

        // generate jwtToken from user data
        var jwtToken = jwtService.generateToken(user);

        // return the AuthenticationResponse object which contains the jwtToken
        return AuthenticationResponse.builder()
                .token(jwtToken)    // pass the jwtToken in AuthenticationResponse and return it
                .build();

    }
}
