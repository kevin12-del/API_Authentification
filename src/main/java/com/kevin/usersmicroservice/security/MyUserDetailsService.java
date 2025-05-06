package com.kevin.usersmicroservice.security;

import com.kevin.usersmicroservice.entities.User;
import com.kevin.usersmicroservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // Récupérer l'utilisateur par son nom d'utilisateur
        User user = userService.findUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        // Liste des autorités
        List<GrantedAuthority> auths = new ArrayList<>();

        // Ajouter le rôle de l'utilisateur (assumé que 'user.getRole()' donne un rôle valide)
        if (user.getRole() != null) {
            auths.add(new SimpleGrantedAuthority("ROLE_" + user.getRole())); // Assure-toi que le rôle est bien précédé de "ROLE_"
        }

        // Créer un objet UserDetails avec les informations de l'utilisateur et les rôles
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getEnabled(),
                true, // account non-expiré
                true, // mot de passe non-expiré
                true, // compte non verrouillé
                auths // les autorités (rôles)
        );
    }
}
