package com.crymuzz.evotingapispring.entity.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO para la respuesta de errores
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CustomErrorResponse {
    // Fecha y hora en que ocurrió el error
    private LocalDateTime datetime;

    // Mensaje que describe el error
    private String message;

    // Detalles adicionales sobre el error
    private String details;
}
