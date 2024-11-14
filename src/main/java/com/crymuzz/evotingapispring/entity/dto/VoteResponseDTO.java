package com.crymuzz.evotingapispring.entity.dto;

import lombok.Data;

import java.time.LocalDateTime;

/**
 * DTO para la respuesta de un voto.
 * <p>
 * Este DTO contiene la información que se devuelve después de registrar un voto,
 * incluyendo un mensaje de confirmación y la hora en que se registró el voto.
 */
@Data
public class VoteResponseDTO {

    private String hashVote;

    // Mensaje de confirmación sobre el registro del voto
    private String message;

    private String statusTransaction;

    // Hora exacta en que se registró el voto
    private LocalDateTime voteTime;
}

