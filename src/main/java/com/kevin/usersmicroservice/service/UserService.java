package com.kevin.usersmicroservice.service;

import com.kevin.usersmicroservice.entities.User;
import com.kevin.usersmicroservice.service.register.RegistrationRequest;

import java.util.List;

public interface UserService {

    User saveUser(User user);
    User findUserByUsername (String username);
    //User login(String username, String password);
    List<User> findAllUsers();
    User registerUser(RegistrationRequest request );
    public void sendEmailUser(User u, String code);
    public User validateToken(String code);
    User forgetPassword(String email);
    User validateNewPassword(String code, String password);
}
