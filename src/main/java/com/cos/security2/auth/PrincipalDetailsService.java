package com.cos.security2.auth;

import com.cos.security2.model.User;
import com.cos.security2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login => 해당 url로 동작을 안한다.
@RequiredArgsConstructor
@Service
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService : loadUserByUsername");
        System.out.println("email : " + email);
        User principal = userRepository.findByEmail(email);
        return new PrincipalDetails(principal);
    }
}
