package com.example.joker.Config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.joker.filter.JwtAuthFilter;
import com.example.joker.service.UserInfoUserDetailsService;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Order(2)
// The class for enabling security
public class SecurityConfig {

    @Autowired
    private JwtAuthFilter authFilter;
    //Returns UserDetailsService
    @Bean
    public UserDetailsService userDetailsService(){
        
        return new UserInfoUserDetailsService();
    }

    //This is the basic Security Filter through which the HTTP request passes through
    //In this we have enabled all permits for welcome and authenticed for the rest of products/** */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        
        return http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(auth ->
                auth.requestMatchers("/products/welcome","/products/new","/products/authenticate").permitAll()
                        .requestMatchers("/products/**")
                        .authenticated()
                        
        )
        .sessionManagement((session)->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //Means we are applying session management
        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class) //Using JwtAuthFilter first
        .httpBasic(Customizer.withDefaults()).build();
    }
    //Encodes the Password into a hased version for saving inside database.
    
    // A method to encode passwords using Bcrypt
    @Bean
    public PasswordEncoder passwordEncode(){
        return new BCryptPasswordEncoder();
    }

    // For authenticating (veryfying the password) using Dao provider
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider=new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncode());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
