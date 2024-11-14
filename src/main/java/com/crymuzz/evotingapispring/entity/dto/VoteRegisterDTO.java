package com.crymuzz.evotingapispring.entity.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO para el registro de un voto.
 * <p>
 * Este DTO contiene la información necesaria para registrar un voto de un estudiante a un candidato,
 * incluyendo el ID del estudiante y el ID del candidato.
 */
@Data
public class VoteRegisterDTO {

    // ID del estudiante que está emitiendo el voto
    @NotBlank(message = "El campo del voto del estudiante no puede estar vacio")
    private Long studentId;

    // ID del candidato al que el estudiante está votando
    @NotBlank(message = "El campo del candidato a votar no puede estar vacio")
    private Long candidateId;
}
