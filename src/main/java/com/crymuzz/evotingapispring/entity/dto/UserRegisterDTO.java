package com.crymuzz.evotingapispring.entity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * DTO para el registro de un usuario.
 * <p>
 * Este DTO contiene los datos necesarios para registrar a un nuevo usuario, incluyendo su nombre,
 * apellido, correo electrónico y contraseña, con validaciones específicas para cada campo.
 */

@Data
public class UserRegisterDTO {

    // Nombre del usuario. No puede estar vacío.
    @NotBlank(message = "El nombre es obligatorio")
    private String firstName;

    // Apellido del usuario. No puede estar vacío.
    @NotBlank(message = "El apellido es obligatorio")
    private String lastName;

    // Correo electrónico del usuario. Debe ser un formato válido y no puede estar vacío.
    @Email(message = "El correo electrónico no es válido")
    @NotBlank(message = "El email es obligatorio")
    private String email;

    // Contraseña del usuario. No puede estar vacía y debe tener al menos 4 caracteres.
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 4, message = "La contraseña debe tener al menos 4 caracteres")
    private String password;

}
