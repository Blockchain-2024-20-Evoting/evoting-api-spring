package com.crymuzz.evotingapispring.entity.dto;

import com.crymuzz.evotingapispring.entity.enums.RoleEnum;
import lombok.Data;

/**
 * DTO para el perfil del usuario.
 * <p>
 * Este DTO contiene la información del perfil de un usuario, incluyendo su correo electrónico,
 * el rol que tiene dentro del sistema, y su nombre y apellido.
 */

@Data
public class UserProfileDTO {
    // Identificador único del usuario
    private Long id;

    // Correo electrónico del usuario
    private String email;

    // Rol del usuario dentro del sistema (usando un enum para definir los roles posibles)
    private RoleEnum role;

    // Primer nombre del usuario
    private String firstName;

    // Apellido del usuario
    private String lastName;
}
