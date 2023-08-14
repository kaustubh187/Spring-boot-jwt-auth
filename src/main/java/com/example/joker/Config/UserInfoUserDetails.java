package com.example.joker.Config;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.stream.Collectors;

import com.example.joker.Entity.User;

public class UserInfoUserDetails  implements UserDetails{
    // Class used to authenticate the users by implementing UserDetails class
    
    private String name;
    private String password;
    private List<GrantedAuthority> authorities;

    //The constructor takes user object as a parameter and  maps it to the UserDetails class
    public UserInfoUserDetails(User user){
        name = user.getName();
        password = user.getPassword();
        authorities = Arrays.stream(user.getRoles().split(","))
                      .map(SimpleGrantedAuthority::new)
                      .collect(Collectors.toList());
    }
    
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return name;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    
}
