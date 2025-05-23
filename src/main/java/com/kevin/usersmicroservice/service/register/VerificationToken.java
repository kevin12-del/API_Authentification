package com.kevin.usersmicroservice.service.register;

import com.kevin.usersmicroservice.entities.User;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Calendar;
import java.util.Date;

@Data
@Entity
@NoArgsConstructor
public class VerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String token;
    private Date expirationTime;
    private boolean resetPassword;
    private static final int EXPIRATION_TIME = 15;
    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
    public VerificationToken(String token, User user, boolean resetPassword) {
        super();
        this.token = token;
        this.user = user;
        this.resetPassword = resetPassword;
        this.expirationTime = this.getTokenExpirationTime();
    }
    public VerificationToken(String token) {
        super();
        this.token = token;
        this.expirationTime = this.getTokenExpirationTime();
    }
    public Date getTokenExpirationTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(new Date().getTime());
        calendar.add(Calendar.MINUTE, EXPIRATION_TIME);
        return new Date(calendar.getTime().getTime());
    }
}

