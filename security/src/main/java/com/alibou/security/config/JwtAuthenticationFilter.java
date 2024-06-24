package com.alibou.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
// any request which we will call from controller will first hit the JwtAuthenticationFilter class where it will check if jwt token is valid or not
// and also it will fetch jwt token if token is valid

@Component
@RequiredArgsConstructor    // this annotation(@RequiredArgsConstructor) will create parameterized constructor with all the final fields in the below class
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;    // this bean will automatically be created using constructor dependency injection by using @RequiredArgsConstructor( we dont need to use @Autowired here)
    private final UserDetailsService userDetailsService;    // create a bean of UserDetailsService so that email can be fetched from db for validation of jwt token
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,    // we want the request, response, filterChain to be not null
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // get the authorization header from the request so that we can pass the token in the header for every call
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // if authHeader is null or it does not starts with "Bearer "
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return; // we dont want to do further execution as check jwt token is failed(invalid jwt token)
        }

        // now extract jwt token from authHeader as jwt token is valid if it reaches this line
        jwt = authHeader.substring(7);  // get the jwt token after "Bearer "
        userEmail = jwtService.extractUsername(jwt);  // todo: extract the userEmail from JWT Token

        // now check if userEmail != null and its not authenticated already.
        // we have to check it in the SecurityContextHolder if user is already authenticated then no need to update SecurityContextHolder else we have to update it
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){    // getAuthentication() == null means user is not authenticated yet
            // get the userDetails from database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // check if jwt is still valid or not
            // if valid then update the SecurityContextHolder and send the request to our DispatcherServlet
            if(jwtService.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // update the SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);


    }
}
