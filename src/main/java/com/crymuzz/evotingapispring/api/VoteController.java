package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.VoteRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.VoteResponseDTO;
import com.crymuzz.evotingapispring.service.IContractVoteService;
import com.crymuzz.evotingapispring.service.IVoteService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.web3j.protocol.exceptions.TransactionException;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Controlador para gestionar operaciones relacionadas los votos
 * Proporciona los endpoints para los votos
 *
 * @author Favio Facundo
 * @version 1.0
 * @since 2024
 */


@RestController
@RequestMapping("/vote")
@Tag(name = "Votos", description = "Endpoint para los votos de las elecciones")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://206.189.238.162:5173")
public class VoteController {

    private final IVoteService voteService;


    private final IContractVoteService contractService;

    /**
     * Registro del voto de un estudiante
     *
     * @param voteRegisterDTO contiene la infomacion del estudiante y candidato a votar
     * @return VoteResponseDTO retorna la informacion del voto
     */

    @PostMapping
    public ResponseEntity<VoteResponseDTO> voteStudent(@RequestBody VoteRegisterDTO voteRegisterDTO) throws TransactionException, IOException {
        VoteResponseDTO response = voteService.vote(voteRegisterDTO);
        return ResponseEntity.ok(response);
    }

    // Endpoint para obtener el conteo de votos de un candidato en una elección
    @GetMapping("/count")
    public ResponseEntity<BigInteger> getVoteCount(
            @RequestParam Long electionId,
            @RequestParam Long candidateId) {
        try {
            BigInteger voteCount = contractService.getVotes(electionId, candidateId);
            return ResponseEntity.ok(voteCount);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(BigInteger.ZERO);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(BigInteger.ZERO);
        }
    }

}
