package com.crymuzz.evotingapispring.security;

import com.crymuzz.evotingapispring.entity.UserEntity;
import com.crymuzz.evotingapispring.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity =
                userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException("No existe el " +
                        "usuario" + username));
        GrantedAuthority grantedAuthority =
                new SimpleGrantedAuthority("ROLE_" + userEntity.getRole().getName().name());

        return new UserPrincipal(userEntity.getId(), userEntity.getEmail(), userEntity.getPassword(),
                Collections.singletonList(grantedAuthority), userEntity);
    }
}
