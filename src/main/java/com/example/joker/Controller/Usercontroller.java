package com.example.joker.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.joker.Entity.AuthRequest;
import com.example.joker.Entity.User;
import com.example.joker.service.JwtService;
import com.example.joker.service.UserService;

@RestController
@RequestMapping("/products")
public class Usercontroller {
    
    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    
    @GetMapping("/welcome")
    public String welcome(){
        return "Welcome to this unsecured free endpoint!";
    }

    // @PostMapping("/new")
    // public String addnewUser(UserInfo userInfo){
    //     return userService.addUser(userInfo);
    // }

    @GetMapping("/getallusers")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> getUsers(){
        return userService.getAllUsers();
    }
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public User getUsers(@PathVariable Integer id){
        User exists = userService.getUserByid(id).orElseThrow(()->new IllegalStateException("User not found"));
        return exists;
    }

    // Endpoint for authentication
    @PostMapping("/authenticate")
    public String authenticateAndGetToken(@RequestBody AuthRequest authRequest){

        //Using authentication manager to authenticate and get our Jwt token
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if(authenticate.isAuthenticated()){
            return jwtService.generateToken(authRequest.getUsername());
        }
        else{
            throw new UsernameNotFoundException("Invalid User request");
        }
        
    }   
}
