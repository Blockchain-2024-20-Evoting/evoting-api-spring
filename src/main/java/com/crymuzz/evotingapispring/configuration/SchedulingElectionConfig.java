package com.crymuzz.evotingapispring.configuration;

import com.crymuzz.evotingapispring.service.IElectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Clase de configuracion para la automatizacion de tareas
 * Funcion: Bean IoC Spring - Contiene el servicio o metodo para actualizar las elecciones
 * Zona: America/Latina
 * Intervalo: Entre 1 minuto o cada dia a la media noche (12:00am)
 */

@Component
@RequiredArgsConstructor
public class SchedulingElectionConfig {

    private final IElectionService electionService;

    /**
     * Tarea automatizada para actualizar el estado de las elecciones
     * Tarea automatizada para el conteo de votos
     */

    @Scheduled(cron = "0 * * * * *", zone = "America/Lima")
    public void scheduleElection() {
        electionService.updateAllStatusElection();
    }

}
