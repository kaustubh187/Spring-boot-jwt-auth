package com.example.joker.service;

import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.example.joker.Entity.User;
import com.example.joker.repository.UserRepository;

@Service
public class UserService {
    
    private final UserRepository userrepo;
    
    public UserService(UserRepository userrepo){
        this.userrepo=userrepo;
    }

    public Optional <User> getUserByid(Integer id){
        return userrepo.findById(id);
    }
    public List<User> getAllUsers(){
        return userrepo.findAll();
    }

    //Creating users (that access APIs and have roles and such)
    // Left for now
   
    
}
