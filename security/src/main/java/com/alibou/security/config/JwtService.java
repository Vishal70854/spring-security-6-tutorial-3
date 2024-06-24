package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // provide a jwt secret key from online key generator(256 bit size minimum requirement)
    // https://asecuritysite.com/encryption/plain
    private static final String SECRET_KEY = "b5eee28c0ac1436d229a464548d5e6ae422369caa5aa1c1659c81e499922f982";

    // overloaded method to generate jwt token by only providing userDetails
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails); // call the below generateToken(claims, userDetails) to generate jwt token
    }

    // method to generate jwt token
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails     // since User class extended UserDetails. so it will fetch the values from user table for UserDetails
    )
    {
        return Jwts
                .builder()
                .setClaims(extraClaims) // set the claims
                .setSubject(userDetails.getUsername())  // subject will be the email of user
                .setIssuedAt(new Date(System.currentTimeMillis()))  // set the issued date and time( as of now used system date and time)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))  // set the expiration date and time( it will be valid for 24 hours and 1000 milliseconds from issueAt time)
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // sign the token with key and HS256 algorithm
                .compact(); // it will generate and return the jwt token as a String
    }

    // method to validate jwt token
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token); // extract the username from jwt token
        return ((username.equals(userDetails.getUsername())) && !isTokenExpired(token));
    }

    // return true if token is expired
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // check if token is expired before current's date
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);  // extract the claim by providing Claims::getExpiration
    }


    // extract the username(which is the email from usertable) from the jwt token
    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject); // extract the username(which is email from db) so pass the token and Claims::getSubject in extractClaim() to get the email from jwt token
    }
    // extract a single claim from jwt token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);  // extract the token in claims variable
        return claimsResolver.apply(claims);    // here we have extracted and returned the claims from jwt token

    }

    // parse the jwt token to get/ access values
    // extract jwt token and parse each field(claims) to get values either from db or from some other areas
    public Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()    // parse the Jwt token
                .setSigningKey(getSignInKey())  // set the sign in key for the jwt token
                .build()
                .parseClaimsJws(token)  // parse the token and now we can extract all fields of jwt token
                .getBody(); // now we can get all the claims which we have inside our jwt token
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);   // decode our secret key in base 64 decoding
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
