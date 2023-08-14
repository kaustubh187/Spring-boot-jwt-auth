package com.example.joker.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtService {
    //Contains various methods for validation, aextraction of username/claims,
    // to check token is expired etc.
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Mapping username to claims
    public String generateToken(String userName){
        Map<String,Object> claims = new HashMap<>();
        return createToken(claims,userName);
    }
    
    // Method to generate a Jwt token
    // Claims are the content: Username is set as content
    // Issued and expiration timestamp are also stored in token itself
    // Uses HS256 algorithm to encode using a 256 bit hex secret key
    public String createToken(Map<String,Object> claims,String userName){
        return Jwts.builder()
        .setClaims(claims)
        .setSubject(userName)
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis()+1000*60*30))
        .signWith(getSignKey(),SignatureAlgorithm.HS256).compact();
    }

    // A decoded secret key generated randomly is sent.
    private Key getSignKey(){
        byte[] keyBytes = Decoders.BASE64.decode("8d556b900109def124d0d94e960b3e5bcef87ed5a1a3bb2d942a1fd21f7afacd");
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
