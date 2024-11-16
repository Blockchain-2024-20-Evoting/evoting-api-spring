package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.CandidateProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.CandidateRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.CandidateResponseDTO;
import com.crymuzz.evotingapispring.service.ICandidateService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

/**
 * Controlador para gestionar operaciones relacionadas con el candidato de las elecciones
 * Proporciona los endpoints para registrar, obtener su images, datos de un candidato, listar y eliminar candidatos
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */
@RestController
@RequestMapping("/v1/candidate")
@Tag(name = "Candidatos", description = "Endpoint para la gestion de candidatos en las elecciones")
@RequiredArgsConstructor
public class CandidateController {

    // Inyeccion de dependencias para el service del candidato
    private final ICandidateService candidateService;

    /**
     * Registra un candidato en el sistema
     *
     * @param candidateRegisterDTO datos a registrar del candidato (firstName, lastName, img, partyId, electionId)
     * @return CandidateResponseDTO contiene la informacion del candidato registrado
     */

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CandidateResponseDTO> registerCandidate(@Valid @ModelAttribute CandidateRegisterDTO candidateRegisterDTO) {
        CandidateResponseDTO response = candidateService.saveCandidate(candidateRegisterDTO);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Obtiene la imagen del candidato por su identificador (id)
     *
     * @param id parametro del identificador del candidato
     * @return Resource retorna el recurso o imagen del candidato
     * @throws IOException Exception lanzada por el servicio de recursos al tener algun error
     */

    @GetMapping("/img/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STUDENT')")
    public ResponseEntity<Resource> getCandidateImg(@PathVariable Long id) throws IOException {
        Resource response = candidateService.findImgCandidateById(id);
        String contentType = Files.probeContentType(response.getFile().toPath());
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(response);
    }

    /**
     * Obtiene la información de un candidato por su identificador (id)
     *
     * @param id parametro del identificador del candidato
     * @return CandidateResponseDTO retorna la información del candidato
     */

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STUDENT')")
    public ResponseEntity<CandidateResponseDTO> getById(@PathVariable Long id) {
        CandidateResponseDTO response = candidateService.findById(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Obtiene la lista de candidatos con su información
     *
     * @return List<CandidateResponseDTO> retorna la información de todos los candidatos
     */

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<CandidateResponseDTO>> getAllCandidates() {
        List<CandidateResponseDTO> response = candidateService.findAll();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Obtiene un perfil general de un candidato (información más detallada)
     *
     * @param id parametro del indentificador del candidato
     * @return CandidateProfileDTO retorna la información detallada del candidato (Partido, Elección)
     */

    @GetMapping("/profile/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STUDENT')")
    public ResponseEntity<CandidateProfileDTO> getProfile(@PathVariable Long id) {
        CandidateProfileDTO response = candidateService.getProfile(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Elimina un candidato del sistema
     *
     * @param id parametro del indentificador del candidato
     * @return Status.NoContent
     */

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteCandidate(@PathVariable Long id) {
        this.candidateService.delete(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    /**
     * Lista los candidatos de una elección en especifica
     *
     * @param id parametro del indentificador de la eleccion
     * @return List<CandidateResponseDTO> lista de candidatos
     */

    @GetMapping("elections/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STUDENT')")
    public ResponseEntity<List<CandidateResponseDTO>> getElections(@PathVariable Long id) {
        List<CandidateResponseDTO> response = candidateService.findByElectionId(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

}
