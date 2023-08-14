package com.example.joker.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.joker.Entity.User;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User,Integer> {
    
    Optional<User> findById(Integer id);
    Optional<User> findByName(String name);
}
