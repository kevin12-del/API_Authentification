package com.kevin.usersmicroservice.service.register;

@lombok.Data
@lombok.NoArgsConstructor
@lombok.AllArgsConstructor
public class RegistrationRequest {
    private String username;
    private String email;
    private String password;
    private String role;
}
