package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.RoleEntity;
import com.crymuzz.evotingapispring.entity.StudentEntity;
import com.crymuzz.evotingapispring.entity.UserEntity;
import com.crymuzz.evotingapispring.entity.dto.AuthResponseDTO;
import com.crymuzz.evotingapispring.entity.dto.LoginDTO;
import com.crymuzz.evotingapispring.entity.dto.UserProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.UserRegisterDTO;
import com.crymuzz.evotingapispring.entity.enums.RoleEnum;
import com.crymuzz.evotingapispring.repository.RoleRepository;
import com.crymuzz.evotingapispring.repository.StudentRepository;
import com.crymuzz.evotingapispring.repository.UserRepository;
import com.crymuzz.evotingapispring.security.UserPrincipal;
import com.crymuzz.evotingapispring.security.jwt.TokenProvider;
import com.crymuzz.evotingapispring.service.IUserService;
import com.crymuzz.evotingapispring.mapper.UserMapper;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements IUserService {

    private final UserRepository userRepository;
    private final StudentRepository studentRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;

    @Override
    public UserProfileDTO saveStudent(UserRegisterDTO student) {
        return registerUserWithRole(student);
    }

    @Override
    @Transactional
    public UserProfileDTO update(Long id, UserProfileDTO userProfileDTO) {

        // Buscar el usuario en la base de datos por su ID
        UserEntity existingUser = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("El usuario no existe"));
        existingUser.setEmail(userProfileDTO.getEmail());

        // Mapear datos adicionales del perfil del estudiante si corresponde
        if (existingUser.getStudent() != null) {
            existingUser.getStudent().setFirstName(userProfileDTO.getFirstName());
            existingUser.getStudent().setLastName(userProfileDTO.getLastName());
            existingUser.getStudent().setUpdatedAt(LocalDateTime.now());
        }

        // Guardar los cambios en la base de datos
        UserEntity updatedUser = userRepository.save(existingUser);

        // Retornar el DTO del usuario actualizado
        return userMapper.toUserProfileDTO(updatedUser);
    }


    @Override
    @Transactional(readOnly = true)
    public UserProfileDTO findById(Long id) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("El usuario con ID " + id + " no existe"));
        return userMapper.toUserProfileDTO(user);
    }

    @Override
    @Transactional
    public AuthResponseDTO login(LoginDTO loginDTO) {
        // Autenticación de usuario -> AuthenticationManager
        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getEmail(),
                        loginDTO.getPassword())
                );

        // Recuperar información
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        UserEntity userEntity = userPrincipal.getUserEntity();

        // Generación del token
        String token = tokenProvider.createAccessToken(authentication);

        return userMapper.toAuthResponseDTO(userEntity, token);
    }


    private UserProfileDTO registerUserWithRole(UserRegisterDTO userRegisterDTO) {
        // Verificar si el email ya está registrado o si existe
        boolean existsByEmail = userRepository.existsByEmail(userRegisterDTO.getEmail());
        boolean existsByFullName = studentRepository.existsByFirstNameAndLastName(userRegisterDTO.getFirstName(),
                userRegisterDTO.getLastName());
        if (existsByEmail)
            throw new IllegalArgumentException("El email ya está registrada");
        if (existsByFullName)
            throw new IllegalArgumentException("Ya existe un usuario con esos nombres");

        RoleEntity roleEntity = roleRepository.findByName(RoleEnum.STUDENT).orElseThrow(() -> new IllegalArgumentException("El role no existe"));

        userRegisterDTO.setPassword(passwordEncoder.encode(userRegisterDTO.getPassword()));

        UserEntity userEntity = userMapper.toUserEntity(userRegisterDTO);
        userEntity.setRole(roleEntity);
        StudentEntity student = new StudentEntity();
        student.setFirstName(userRegisterDTO.getFirstName());
        student.setLastName(userRegisterDTO.getLastName());
        student.setCreatedAt(LocalDateTime.now());
        student.setUser(userEntity);
        userEntity.setStudent(student);
        UserEntity savedUser = userRepository.save(userEntity);
        return userMapper.toUserProfileDTO(savedUser);
    }

}
