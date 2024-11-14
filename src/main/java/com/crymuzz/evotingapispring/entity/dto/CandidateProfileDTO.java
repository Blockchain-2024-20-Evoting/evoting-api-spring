package com.crymuzz.evotingapispring.entity.dto;

import lombok.Data;

/**
 * DTO para el perfil de un candidato
 */
@Data
public class CandidateProfileDTO {
    // Identificador único del candidato
    private Long id;

    // Nombre del candidato
    private String firstName;

    // Apellido del candidato
    private String lastName;

    // URL de la imagen del candidato
    private String image;

    // Información del partido al que pertenece el candidato
    private PartyResponseDTO party;

    // Información de la elección en la que participa el candidato
    private ElectionResponseDTO election;
}
