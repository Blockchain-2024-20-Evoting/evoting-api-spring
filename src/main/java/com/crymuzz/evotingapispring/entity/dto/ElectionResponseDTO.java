package com.crymuzz.evotingapispring.entity.dto;

import com.crymuzz.evotingapispring.entity.enums.StateElectionEnum;
import lombok.Data;

import java.time.LocalDate;

/**
 * DTO para la respuesta de una elección.
 */
@Data
public class ElectionResponseDTO {
    // Identificador único de la elección
    private Long id;

    // Nombre de la elección
    private String name;

    // Fecha de inicio de la elección
    private LocalDate startDate;

    // Fecha de finalización de la elección
    private LocalDate endDate;

    // Estado actual de la elección (utiliza el enum StateElectionEnum para los estados posibles)
    private StateElectionEnum state;
}