package com.kevin.usersmicroservice.service.register;

import com.kevin.usersmicroservice.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationTokenRepository extends
        JpaRepository<VerificationToken, Long> {
    VerificationToken findByToken(String token);

    VerificationToken findByUser(User user);
}
