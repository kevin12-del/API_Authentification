package com.kevin.usersmicroservice.service;


import com.kevin.usersmicroservice.entities.User;
import com.kevin.usersmicroservice.repos.UserRepository;
import com.kevin.usersmicroservice.service.exceptions.EmailAlreadyExistsException;
import com.kevin.usersmicroservice.service.exceptions.ExpiredTokenException;
import com.kevin.usersmicroservice.service.exceptions.InvalidTokenException;
import com.kevin.usersmicroservice.service.register.RegistrationRequest;
import com.kevin.usersmicroservice.service.register.VerificationToken;
import com.kevin.usersmicroservice.service.register.VerificationTokenRepository;
import com.kevin.usersmicroservice.util.EmailSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Transactional
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;
    
    @Autowired
    VerificationTokenRepository verificationTokenRepo;

    @Autowired
    EmailSender emailSender;

    @Override
    public User saveUser(User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
        //return userRepository.save(user);
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public User registerUser(RegistrationRequest request) {
        Optional<User> optionalUser = userRepository.findByEmail(request.getEmail());

        if(optionalUser.isPresent()) {
            throw new EmailAlreadyExistsException("Email address already in use.");
        }
        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setPassword(bCryptPasswordEncoder.encode(request.getPassword()));

        newUser.setEnabled(false);
        newUser.setRole(User.Role.valueOf(request.getRole()));
        userRepository.save(newUser);

        //génére le code secret
        String code = this.generateCode();
        VerificationToken token = new VerificationToken(code, newUser, false );
        
        verificationTokenRepo.save(token);

        //envoyer par email pour valider l'email de l'utilisateur
        sendEmailUser(newUser,token.getToken());

        return userRepository.save(newUser);
    }

    private String generateCode() {
        Random random = new Random();
        Integer code = 100000 + random.nextInt(900000);

        return code.toString();
    }

    @Override
    public void sendEmailUser(User u, String code) {
        String emailBody ="Bonjour "+ "<h1>"+u.getUsername() +"</h1>" +
                " Votre code de validation est "+"<h1>"+code+"</h1>";
        emailSender.sendEmail(u.getEmail(), emailBody);
    }


    @Override
    public User validateToken(String code) {
        VerificationToken token = verificationTokenRepo.findByToken(code);
        if (token == null) {
            throw new InvalidTokenException("Invalid Token");
        }
        User user = token.getUser();
        Calendar calendar = Calendar.getInstance();
        if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
            verificationTokenRepo.delete(token);
            throw new ExpiredTokenException("expired Token");
        }
        user.setEnabled(true);
        userRepository.save(user);
        return user;
    }

    @Override
    public User validateNewPassword(String code, String password){
        VerificationToken token = verificationTokenRepo.findByToken(code);
        if (token == null) {
            throw new InvalidTokenException("Invalid Token");
        }
        User user = token.getUser();
        Calendar calendar = Calendar.getInstance();
        if ((token.getExpirationTime().getTime() - calendar.getTime().getTime()) <= 0) {
            verificationTokenRepo.delete(token);
            throw new ExpiredTokenException("expired Token");
        }

        user.setPassword(bCryptPasswordEncoder.encode(password));
        userRepository.save(user);
        return user;
    }

    public User forgetPassword(String email){
        User user = userRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
        String code = this.generateCode();

        Optional<VerificationToken> existingToken = Optional.ofNullable(verificationTokenRepo.findByUser(user));

        if (existingToken.isPresent()) {
            verificationTokenRepo.delete(existingToken.get());
        }

        VerificationToken token = new VerificationToken(code, user, true);

        verificationTokenRepo.save(token);

        //envoyer par email pour valider l'email de l'utilisateur
        sendEmailUser(user,token.getToken());
        return user;
    }
}


