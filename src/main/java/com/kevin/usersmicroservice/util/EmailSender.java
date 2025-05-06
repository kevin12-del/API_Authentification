package com.kevin.usersmicroservice.util;

public interface EmailSender {
    void sendEmail(String toEmail, String body);
}
