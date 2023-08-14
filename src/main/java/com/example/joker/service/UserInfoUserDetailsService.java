package com.example.joker.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.example.joker.Config.UserInfoUserDetails;
import com.example.joker.Entity.User;
import com.example.joker.repository.UserRepository;

// Service Class for UserInfoUser details
@Component 
public class UserInfoUserDetailsService implements UserDetailsService{
    @Autowired
    private UserRepository repository;
    
    // Takes in string as an input and then finds the UserInfo object corresponding to name
    // Then it maps this UserInfo to UserInfoDetails 
    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        Optional<User> user = repository.findByName(name);
        return user.map(UserInfoUserDetails::new)
                .orElseThrow(()-> new UsernameNotFoundException("Username not found"));
        
    }
    
}
