package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.UserProfileDTO;
import com.crymuzz.evotingapispring.service.IUserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


/**
 * Controlador para gestionar operaciones relacionadas los estudiantes
 * Proporciona los endpoints para obtener el perfil y actualizar datos de un estudiante
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */

@RestController
@RequestMapping("/profile")
@Tag(name = "Estudiantes", description = "Endpoint para las consultas de los estudiantes")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://206.189.238.162:5173")
public class StudentController {

    private final IUserService userService;

    /**
     * Actualiza la informacion de un estudiante
     *
     * @param id             parametro del identificador del estudiante
     * @param userProfileDTO contiene la informacion a modificar del estudiante
     * @return UserProfileDTO tiene la informacion actualizada del estudiante
     */

    // Obtener su perfil por su ID
    @PutMapping("/{id}")
    public ResponseEntity<UserProfileDTO> updateProfile(@PathVariable Long id, @RequestBody UserProfileDTO userProfileDTO) {
        UserProfileDTO updateProfile = userService.update(id, userProfileDTO);
        return ResponseEntity.ok(updateProfile);
    }

    /**
     * Obtiene el perfil detallado de un estudiante
     *
     * @param id parametro del identificador del estudiante
     * @return UserProfileDTO tiene la informacion del estudiante
     */
    // Actualizar su perfil
    @GetMapping("/{id}")
    public ResponseEntity<UserProfileDTO> getProfile(@PathVariable Long id) {
        UserProfileDTO userProfileDTO = userService.findById(id);
        return ResponseEntity.ok(userProfileDTO);
    }
}
