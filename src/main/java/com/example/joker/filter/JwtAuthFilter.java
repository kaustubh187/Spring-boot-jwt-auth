package com.example.joker.filter;


import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.joker.service.JwtService;
import com.example.joker.service.UserInfoUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthFilter extends OncePerRequestFilter{
    
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserInfoUserDetailsService userDetailsService;
    
    //Each request goes through this filter
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException{
        // From the request we extract auth token    
        String authHeader = request.getHeader("Authorization");
            String token=null;
            String username=null;
            // All Jwt tokens contain a "Bearer " header spring 2.7 onwards we 
            // need to extract it in order to perform operations.
            if(authHeader!=null && authHeader.startsWith("Bearer ")){
                token=authHeader.substring(7);
                username = jwtService.extractUsername(token);
                 
            }
            // Security Context holder stores the information about currently authenticated user.
            // If it's null we need to enter information
            if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                // First we validate our token
                if(jwtService.validateToken(token,userDetails)){
                // After validation an authentication token is genrated
                  UsernamePasswordAuthenticationToken authtoken = new UsernamePasswordAuthenticationToken( userDetails,null,userDetails.getAuthorities());
                  //Sets additional details in the token for authentication request
                  authtoken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); 
                  //Sets this token in the holder meaning user is NOW AUTHENTICATED!
                  SecurityContextHolder.getContext().setAuthentication(authtoken);
                }
            }
            //Allows our request to proceed for next filters...
            filterChain.doFilter(request, response);
    }
    
    

    
}
