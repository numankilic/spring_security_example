package com.example.security_example.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;


public interface ApplicationUserDao {

    Optional<ApplicationUser> findByUsername(String username);
}
