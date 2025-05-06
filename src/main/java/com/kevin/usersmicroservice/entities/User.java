package com.kevin.usersmicroservice.entities;

import java.util.List;

import jakarta.persistence.*;
import lombok.*;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User {
    @Id
    @GeneratedValue (strategy=GenerationType.IDENTITY)
    private Long user_id;

    @Column(unique=true)
    private String username;
    private String password;
    private Boolean enabled;
    private String email;

    @Enumerated(EnumType.STRING)
    private Role role;

    public enum Role {
        ADMIN, ENSEIGNANT, ELEVE, PARENT
    }
}
