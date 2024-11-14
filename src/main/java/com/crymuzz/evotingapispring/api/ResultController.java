package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.ResultResponseDTO;
import com.crymuzz.evotingapispring.service.impl.ResultServiceImpl;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador para gestionar operaciones relacionadas los resultados
 * Proporciona el endpoint para obtener los resultadod de una eleccion
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */

@RestController
@RequestMapping("v1/results")
@Tag(name = "Resultados", description = "Endpoint para las consultas de los resultados")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://206.189.238.162:5173")
public class ResultController {

    private final ResultServiceImpl resultService;

    /**
     * Obtiene los resultados de una eleccion por su identificador
     *
     * @param id parametro del identificador de la eleccion
     * @return List<ResultResponseDTO> contiene la lista de candidatos con su informacion y estadistica
     */

    @GetMapping("/{id}")
    public ResponseEntity<List<ResultResponseDTO>> getResultElection(@PathVariable Long id) {
        List<ResultResponseDTO> response = resultService.getResultsByElection(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

}
