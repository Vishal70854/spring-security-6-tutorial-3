package com.alibou.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity  // to enable spring security we have to use this annotation
@RequiredArgsConstructor    // inorder to inject dependencies of some special class(Annotated classes) always use final with the class where we declare the object field. using final will automatically inject dependencies of that object
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;    // inject dependency of JwtAuthenticationFilter by using the final keyword. it is because we have use @RequiredArgsConstructor in class declaration above
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        http
                .csrf(csrf -> csrf.disable())   // disable csrf
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/api/v1/auth/**").permitAll()   // permit all http requests with"/api/v1/auth/**"
                        .anyRequest().authenticated()   // authenticate all other requests (since we mentioned "/api/v1/auth/**" now all the enpoints will be permitted directly)
                )
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
