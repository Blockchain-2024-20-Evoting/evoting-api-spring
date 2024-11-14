package com.crymuzz.evotingapispring.entity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

/**
 * DTO para el registro de un partido.
 * Este DTO contiene los datos necesarios para registrar un partido político, incluyendo el nombre, la descripción y la imagen del partido.
 */

@Data
@Builder
public class PartyRegisterDTO {
    // Nombre del partido. No puede estar vacío.
    @NotBlank(message = "¡El nombre del equipo no puede estar vacio!")
    private String name;

    // Descripción del partido. No puede estar vacía.
    @NotBlank(message = "¡La descripción del partido no puede estar vacia!")
    private String description;

    // Imagen del partido. No puede ser nula.
    @NotNull(message = "La imagen del equipo es obligatoria")
    private MultipartFile img;
}