package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.AuthResponseDTO;
import com.crymuzz.evotingapispring.entity.dto.LoginDTO;
import com.crymuzz.evotingapispring.entity.dto.UserProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.UserRegisterDTO;
import com.crymuzz.evotingapispring.service.IUserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador para gestionar operaciones relacionadas con autenticación y registro
 * Proporciona el endpoint para registrar un estudiante siendo administrador
 * Proporciona el endpoint para logearse en la API
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */
@RestController
@RequestMapping("/auth")
@Tag(name = "Autenticacion", description = "Endpoint para el registro de estudiantes y autenticacion de usuarios")
@RequiredArgsConstructor
public class AuthController {

    private final IUserService userService;

    /**
     * Registra a un nuevo estudiante en el sistema.
     *
     * @param userRegisterDTO datos del estudiante (firstName,lastName,email,password)
     * @return UserProfileDTO que tiene los datos generales del estudiante registrado y el status de respuesta
     */

    @PostMapping("/register/student")
    public ResponseEntity<UserProfileDTO> registerStudent(@Valid @RequestBody UserRegisterDTO userRegisterDTO) {
        UserProfileDTO userProfile = userService.saveStudent(userRegisterDTO);
        return new ResponseEntity<>(userProfile, HttpStatus.CREATED);
    }

    /**
     * Autentica a un usuario en el sistema.
     *
     * @param loginDTO datos de autenticacion del usuario (email, password)
     * @return AuthResponseDTO que contiene el token de autenticacion, datos del usuario y el status de respuesta
     */

    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@RequestBody @Valid LoginDTO loginDTO) {
        AuthResponseDTO authResponseDTO = userService.login(loginDTO);
        return ResponseEntity.ok(authResponseDTO);
    }

}
