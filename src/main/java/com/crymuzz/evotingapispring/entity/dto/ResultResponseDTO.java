package com.crymuzz.evotingapispring.entity.dto;

import com.crymuzz.evotingapispring.entity.CandidateEntity;
import jakarta.persistence.*;
import lombok.Builder;
import lombok.Data;

/**
 * DTO para la respuesta de resultados de una elección.
 * <p>
 * Este DTO contiene la información sobre los resultados de un candidato en una elección,
 * incluyendo su nombre, el nombre de la elección, el partido, el número de votos, si es el ganador
 * y su porcentaje de votos.
 */

@Data
@Builder
public class ResultResponseDTO {

    private Long id;

    private CandidateEntity candidateEntity;

    private Long countVotes;

    private double percentages;

    private boolean isWinner;

    private String partyName;

    private String electionName;

}
