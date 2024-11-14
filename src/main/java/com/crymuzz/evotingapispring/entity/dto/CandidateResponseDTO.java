package com.crymuzz.evotingapispring.entity.dto;

import lombok.Data;


/**
 * DTO para la respuesta del registro del candidato
 */
@Data
public class CandidateResponseDTO {
    // Identificador único del candidato
    private Long id;

    // Nombre del candidato
    private String firstName;

    // Apellido del candidato
    private String lastName;

    // URL de la imagen del candidato
    private String image;

    // Nombre del partido al que pertenece el candidato
    private String partyName;

    // Nombre de la elección en la que participa el candidato
    private String electionName;
}