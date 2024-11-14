package com.crymuzz.evotingapispring.entity.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para el inicio de sesión del usuario.
 * Este DTO contiene los datos necesarios para realizar el inicio de sesión, como el correo electrónico y la contraseña,
 * con validaciones aplicadas sobre estos campos.
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginDTO {
    // Correo electrónico del usuario. Debe ser válido y no puede estar vacío.
    @Email(message = "El correo electrónico no es válido")
    @NotBlank(message = "El correo es obligatorio")
    private String email;

    // Contraseña del usuario. No puede estar vacía.
    @NotBlank(message = "La contraseña es obligatoria")
    private String password;
}
