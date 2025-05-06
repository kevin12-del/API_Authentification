package com.kevin.usersmicroservice.restControllers;

import com.kevin.usersmicroservice.entities.User;
import com.kevin.usersmicroservice.repos.UserRepository;
import com.kevin.usersmicroservice.service.UserService;
import com.kevin.usersmicroservice.service.register.RegistrationRequest;
import com.kevin.usersmicroservice.service.register.VerificationToken;
import com.kevin.usersmicroservice.service.register.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class UserRestController {

    @Autowired
    VerificationTokenRepository tokenRepository;

    @Autowired
    UserService userService;
    @Autowired
    private UserRepository userRepository;

    //@RequestMapping(path = "all", method = RequestMethod.GET)
    @GetMapping("/all")
    public List<User> getAllUsers(){
        return  userRepository.findAll();
    }

    @PostMapping("/register")
    public User register(@RequestBody RegistrationRequest request){
        return userService.registerUser(request);
    }


    @GetMapping("/verifyEmail/{token}")
    public User verifyEmail(@PathVariable("token") String token){
        return userService.validateToken(token);
    }

    @GetMapping("/forgetPassword/{email}")
    public User forgetPassword(@PathVariable("email") String email) {
        return userService.forgetPassword(email);
    }

    @PostMapping("/resetPassword/{code}")
    public User resetPassword(@PathVariable("code")String code, @RequestBody User user){
        return userService.validateNewPassword(code, user.getPassword());
    }

    @DeleteMapping("/delete/{email}")
    public void deleteUser(@PathVariable("email") String email) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));
        VerificationToken verificationToken = tokenRepository.findByUser(user);
        tokenRepository.delete(verificationToken);
        userRepository.delete(user);
    }
}
