package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.PartyRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.PartyResponseDTO;
import com.crymuzz.evotingapispring.service.IPartyService;
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
 * Controlador para gestionar operaciones relacionadas con los partidos
 * Proporciona los endpoints para registrar, obtener su imagen, obtener, listar y eliminar partidos
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */

@RestController
@RequestMapping("/v1/party")
@Tag(name = "Partidos", description = "Endpoint para la gestion de partidos de los candidatos")
@RequiredArgsConstructor
public class PartyController {

    // Inyeccion de dependencias en el servicio de partidos
    private final IPartyService partyService;

    /**
     * Registra un partido en el sistema
     *
     * @param partyRegisterDTO datos del partido a registrar (name, descripcion, img)
     * @return PartyResponseDTO contiene la información del partido creado
     */

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PartyResponseDTO> create(@Valid @ModelAttribute PartyRegisterDTO partyRegisterDTO) {
        PartyResponseDTO response = partyService.saveParty(partyRegisterDTO);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    /**
     * Obtiene el recurso o imagen del partido
     *
     * @param id parametro del identificacdor del partido
     * @return Recurso o imagen del partido
     * @throws IOException exception por cualquier error en la recuperacion o guardado del recurso
     */

    @GetMapping("/img/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STUDENT')")
    public ResponseEntity<Resource> getPartyImg(@PathVariable Long id) throws IOException {
        Resource response = partyService.findImgPartyById(id);
        String contentType = Files.probeContentType(response.getFile().toPath());
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, contentType).body(response);
    }

    /**
     * Lista todos los partidos
     *
     * @return List<PartyResponseDTO> obtiene todos los partidos registrados
     */


    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PartyResponseDTO>> getAll() {
        return ResponseEntity.ok(partyService.findAll());
    }

    /**
     * Obtener un partido por su identificador
     *
     * @param id parametro del identificador del partido
     * @return PartyResponseDTO contiene la información detallada de un partido
     */

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'STUDENT')")
    public ResponseEntity<PartyResponseDTO> getById(@PathVariable Long id) {
        PartyResponseDTO response = partyService.findById(id);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    /**
     * Elimina un partido del sistema
     *
     * @param id parametro del identificador del partido
     * @return Status.NoContent
     */

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteParty(@PathVariable Long id) {
        this.partyService.delete(id);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
