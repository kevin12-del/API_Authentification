package com.kevin.usersmicroservice.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kevin.usersmicroservice.entities.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super();
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        if (!request.getServletPath().equals("/login")) {
            return null; // Ignore si ce n’est pas /login
        }
        User user = null;

        try {
            // Récupérer les informations de l'utilisateur depuis la requête
            user = new ObjectMapper().readValue(request.getInputStream(), User.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Créer une demande d'authentification avec le nom d'utilisateur et le mot de passe
        return authenticationManager.
                authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        org.springframework.security.core.userdetails.User springUser = (org.springframework.security.core.userdetails.User) authResult.getPrincipal();

        // On récupère le rôle directement depuis l'utilisateur Spring
        String role = springUser.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .findFirst().orElse("USER"); // Si aucun rôle trouvé, on prend "USER" par défaut

        // Création du JWT avec le nom d'utilisateur et le rôle
        String jwt = JWT.create()
                .withSubject(springUser.getUsername()) // Nom d'utilisateur
                .withClaim("role", role) // Ajouter le rôle au token
                .withExpiresAt(new Date(System.currentTimeMillis() + SecParams.EXP_TIME)) // Expiration du token
                .sign(Algorithm.HMAC256(SecParams.SECRET)); // Signature avec la clé secrète

        // Ajouter le token JWT dans l'entête de la réponse
        response.addHeader("Authorization", "Bearer " + jwt);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        if (failed instanceof DisabledException) {
            // Réponse d'erreur si l'utilisateur est désactivé
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            Map<String, Object> data = new HashMap<>();
            data.put("errorCause", "disabled");
            data.put("message", "L'utilisateur est désactivé !");
            ObjectMapper objectMapper = new ObjectMapper();
            String json = objectMapper.writeValueAsString(data);
            PrintWriter writer = response.getWriter();
            writer.println(json);
            writer.flush();
        } else {
            super.unsuccessfulAuthentication(request, response, failed);
        }
    }
}
