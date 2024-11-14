package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.ElectionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.ElectionResponseDTO;
import com.crymuzz.evotingapispring.service.IElectionService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador para gestionar operaciones relacionadas con las elecciones
 * Proporciona los endpoints para registrar, obtener su images, obtener, listar y eliminar elecciones
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */

@RestController
@RequestMapping("/v1/election")
@Tag(name = "Elecciones", description = "Endpoint para la gestion de elecciones de las votaciones")
@RequiredArgsConstructor
public class ElectionController {

    // Inyeccion de dependencias para el service eleccion
    private final IElectionService electionService;

    /**
     * Registra una eleccion en el sistema
     *
     * @param electionRegisterDTO datos de la eleccion a registrar (name, startDate, endDate)
     * @return ElectionResponseDTO contiene la información de al eleccion creada con su estado actual
     */

    @PostMapping
    public ResponseEntity<ElectionResponseDTO> create(@RequestBody @Valid ElectionRegisterDTO electionRegisterDTO) {
        ElectionResponseDTO response = electionService.saveElection(electionRegisterDTO);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Obtiene la lista de elecciones
     *
     * @return List<ElectionResponseDTO> contiene la informacion de todas las elecciones
     */

    @GetMapping
    public ResponseEntity<List<ElectionResponseDTO>> getAll() {
        return ResponseEntity.ok(this.electionService.findAll());
    }

    /**
     * Obtiene la informacion de una eleccion por su identificador (id)
     *
     * @param id parametro del identificador de la eleccion
     * @return ElecionResponseDTO contiene la información detallada de la eleccion
     */

    @GetMapping("/{id}")
    public ResponseEntity<ElectionResponseDTO> getById(@PathVariable Long id) {
        ElectionResponseDTO response = this.electionService.findById(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Elimina una eleccion de sistema
     *
     * @param id parametro del identificador de la eleccion
     * @return Status.NoContent
     */

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteElection(@PathVariable Long id) {
        this.electionService.delete(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }


}
