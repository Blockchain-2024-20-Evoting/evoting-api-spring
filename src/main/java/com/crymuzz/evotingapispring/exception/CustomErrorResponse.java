package com.crymuzz.evotingapispring.exception;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CustomErrorResponse {
    private LocalDateTime dateTime;
    private String message;
    private String details;
    private Map<String, String> fieldErrors; // Nuevo campo para errores específicos de campos

    // Constructor adicional para compatibilidad sin errores de campo
    public CustomErrorResponse(LocalDateTime dateTime, String message, String details) {
        this.dateTime = dateTime;
        this.message = message;
        this.details = details;
    }
}
