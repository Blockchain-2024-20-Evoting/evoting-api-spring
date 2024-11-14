package com.crymuzz.evotingapispring.entity.dto;

import lombok.Data;

/**
 * DTO para la respuesta de un partido.
 * <p>
 * Este DTO contiene la información que se devuelve cuando se solicita un partido,
 * incluyendo su ID, nombre, descripción e imagen.
 */

@Data
public class PartyResponseDTO {
    // Identificador único del partido
    private Long id;

    // Nombre del partido
    private String name;

    // Descripción del partido
    private String description;

    // URL o ruta de la imagen del partido
    private String img;
}
