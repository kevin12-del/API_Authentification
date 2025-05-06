package com.kevin.usersmicroservice.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws IOException, ServletException {

        String path = request.getServletPath();

        // Ignorer les routes publiques (vérifie si le chemin contient les termes)
        if (path.contains("/login") || path.contains("/register") || path.contains("/verifyEmail") || path.contains("/delete")|| path.contains("/forgetPassword")|| path.contains("/resetPassword")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = request.getHeader("Authorization");
        if(jwt == null || !jwt.startsWith(SecParams.TOKEN_PREFIX)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Missing or invalid Authorization header");
            return;
        }

        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecParams.SECRET)).build();
        jwt = jwt.substring(SecParams.TOKEN_PREFIX.length()); // Remove "Bearer " prefix

        DecodedJWT decodedJWT = verifier.verify(jwt);
        String username = decodedJWT.getSubject();

        // Récupérer le rôle du token (ajusté selon l'ajout de la claim "role")
        String role = decodedJWT.getClaim("role").asString();

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        // Ajouter le rôle comme autorité
        authorities.add(new SimpleGrantedAuthority(role));

        // Créer un objet d'authentification pour l'utilisateur
        UsernamePasswordAuthenticationToken user =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        // Mettre l'utilisateur dans le contexte de sécurité
        SecurityContextHolder.getContext().setAuthentication(user);

        filterChain.doFilter(request, response);
    }
}
