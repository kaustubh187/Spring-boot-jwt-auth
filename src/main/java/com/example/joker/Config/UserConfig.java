package com.example.joker.Config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.joker.Entity.User;
import com.example.joker.repository.UserRepository;

@Configuration
@Order(1)
public class UserConfig {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Bean
    CommandLineRunner commalini(UserRepository userrepo)
    {
        return args->{
            User James = new User(
                "James",
                "Bond007",
                passwordEncoder.encode("pwd1"),
                "Secret Service",
                34,
                "ROLE_ADMIN"
            );
            User Johny = new User(
                "Johny",
                "English09",
                passwordEncoder.encode("pwd2"),
                "MI7",
                41,
                "ROLE_USER"
            );
            userrepo.save(James);
            userrepo.save(Johny);
        };
    }
}
