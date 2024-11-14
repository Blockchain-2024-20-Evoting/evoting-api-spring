package com.crymuzz.evotingapispring.entity.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.ZoneId;

/**
 * DTO para registrar una elección.
 * Este DTO contiene los datos necesarios para registrar una elección, incluyendo su nombre, fechas de inicio y fin,
 * y validaciones sobre las fechas.
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ElectionRegisterDTO {

    // Nombre de la elección. No puede ser nulo o estar en blanco.
    @NotBlank(message = "El campo del nombre no puede ser nulo o en blanco")
    private String name;

    // Fecha de inicio de la elección. No puede ser nula y debe ser en el futuro.
    @NotNull(message = "La fecha de inicio de la elección no puede ser nula")
    @Future // Verifica que la fecha esté en el futuro
    private LocalDate startDate;

    // Fecha de finalización de la elección. No puede ser nula y debe ser en el futuro.
    @NotNull(message = "La fecha de finalización de la elección no puede ser nula")
    @Future // Verifica que la fecha esté en el futuro
    private LocalDate endDate;

    // Valida que la fecha de finalización sea posterior a la fecha de inicio.
    @AssertTrue(message = "La fecha de fin debe ser mayor que la fecha de inicio")
    public boolean isEndDateAfterStartDate() {
        return endDate.isAfter(startDate); // Verifica que endDate sea estrictamente posterior a startDate
    }

    // Valida que la fecha de inicio no sea anterior a la fecha actual.
    @AssertTrue(message = "La fecha de inicio no puede ser anterior a la fecha actual")
    public boolean isStartDateNotBeforeToday() {
        return !startDate.isBefore(LocalDate.now(ZoneId.of("America/Lima"))); // Verifica que la fecha de inicio no sea antes de hoy
    }

    // Valida que la fecha de inicio no sea igual a la fecha de finalización.
    @AssertTrue(message = "La fecha de inicio y de finalización no pueden ser iguales")
    public boolean isStartDateNotEqualToEndDate() {
        return !startDate.isEqual(endDate); // Verifica que las fechas no sean iguales
    }
}
