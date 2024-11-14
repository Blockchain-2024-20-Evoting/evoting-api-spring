package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.CandidateEntity;
import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.ResultEntity;
import com.crymuzz.evotingapispring.entity.dto.ResultResponseDTO;
import com.crymuzz.evotingapispring.entity.enums.StateElectionEnum;
import com.crymuzz.evotingapispring.exception.ResourceNotFoundException;
import com.crymuzz.evotingapispring.mapper.ResultMapper;
import com.crymuzz.evotingapispring.repository.CandidateRepository;
import com.crymuzz.evotingapispring.repository.ResultRepository;
import com.crymuzz.evotingapispring.service.IContractVoteService;
import com.crymuzz.evotingapispring.service.IResultService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ResultServiceImpl implements IResultService {

    private final ResultRepository resultRepository;
    private final CandidateRepository candidateRepository;
    private final IContractVoteService contractService;
    private final ResultMapper resultMapper;


    @Override
    @Transactional
    public void countVotes(ElectionEntity electionEntity) {

        // Verificar que la elección esté inactiva antes de contar los votos
        if (electionEntity.getState() != StateElectionEnum.INACTIVE) {
            throw new ResourceNotFoundException("La elección aún no ha finalizado");
        }

        // Obtener candidatos y contar votos desde el contrato
        List<CandidateEntity> candidates = candidateRepository.findCandidateEntityByElectionId(electionEntity.getId());
        Map<Long, Long> countVotesContract = new HashMap<>();

        // Obtener votos para cada candidato y almacenar en Map con Long en lugar de BigInteger
        candidates.forEach(candidate -> {
            try {
                BigInteger votesBigInt = contractService.getVotes(candidate.getElection().getId(), candidate.getId());
                long votes = votesBigInt.longValueExact();
                countVotesContract.put(candidate.getId(), votes);
            } catch (IOException e) {
                throw new RuntimeException("Error obteniendo votos para el candidato ID: " + candidate.getId(), e);
            } catch (ArithmeticException e) {
                throw new RuntimeException("El número de votos excede el límite de Long para el candidato ID: " + candidate.getId(), e);
            }
        });

        // Calcular el total de votos y el máximo para determinar el ganador
        long totalVotes = countVotesContract.values().stream().mapToLong(Long::longValue).sum();
        long maxVotes = countVotesContract.values().stream().mapToLong(Long::longValue).max().orElse(0L);

        // Crear lista de resultados para cada candidato
        List<ResultEntity> results = new ArrayList<>();

        for (CandidateEntity candidate : candidates) {
            long voteCount = countVotesContract.getOrDefault(candidate.getId(), 0L);
            boolean isWinner = (voteCount == maxVotes);
            double percentage = (totalVotes > 0) ? (voteCount * 100.0) / totalVotes : 0.0;

            // Crear ResultEntity para cada candidato
            ResultEntity result = new ResultEntity(
                    null,
                    candidate,
                    voteCount,
                    percentage,
                    isWinner,
                    candidate.getParty().getName(),
                    electionEntity.getName()
            );
            results.add(result);
        }
        // Guardar resultados
        resultRepository.saveAll(results);
    }


    @Override
    public Long getVotesCandidate(Long candidateId) throws IOException {
        CandidateEntity candidate =
                candidateRepository.findById(candidateId).orElseThrow(() -> new ResourceNotFoundException(
                        "Candidado a" +
                                " " +
                                "consultar votos no encontrado"));
        BigInteger voteCount = contractService.getVotes(candidate.getElection().getId(), candidate.getId());
        return voteCount.longValueExact();
    }

    @Override
    public List<ResultResponseDTO> getResultsByElection(Long electionId) {
        return resultRepository.findResultEntityByCandidateEntityElectionId(electionId).stream().map(resultMapper::toResultResponseDTO).toList();
    }
}
