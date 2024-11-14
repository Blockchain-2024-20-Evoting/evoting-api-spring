package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.dto.ElectionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.ElectionResponseDTO;
import com.crymuzz.evotingapispring.entity.enums.StateElectionEnum;
import com.crymuzz.evotingapispring.exception.BadRequestException;
import com.crymuzz.evotingapispring.exception.ResourceNotFoundException;
import com.crymuzz.evotingapispring.repository.ElectionRepository;
import com.crymuzz.evotingapispring.service.IElectionService;
import com.crymuzz.evotingapispring.mapper.ElectionMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ElectionServiceImpl implements IElectionService {

    private final ElectionRepository electionRepository;
    private final ElectionMapper electionMapper;
    private final ResultServiceImpl resultService;

    @Override
    @Transactional
    public ElectionResponseDTO saveElection(ElectionRegisterDTO electionDTO) {
        if (electionRepository.existsByName(electionDTO.getName())) {
            throw new BadRequestException("La elección ya existe");
        }
        ElectionEntity electionEntity = electionMapper.toElectionEntity(electionDTO);
        electionEntity.setState(determineElectionState(electionEntity.getStartDate(), electionEntity.getEndDate()));
        ElectionEntity response = electionRepository.save(electionEntity);
        return electionMapper.toElectionResponse(response);
    }

    private StateElectionEnum determineElectionState(LocalDate startDate, LocalDate endDate) {
        LocalDate now = LocalDate.now(ZoneId.of("America/Lima"));
        return now.isBefore(startDate) ? StateElectionEnum.PENDING : StateElectionEnum.ACTIVE;
    }

    @Override
    @Transactional(readOnly = true)
    public List<ElectionResponseDTO> findAll() {
        return electionRepository.findAll().stream().map(electionMapper::toElectionResponse).toList();
    }

    @Override
    @Transactional(readOnly = true)
    public ElectionResponseDTO findById(Long id) {
        Optional<ElectionEntity> response = this.electionRepository.findById(id);
        return response.map(electionMapper::toElectionResponse).orElseThrow(() -> new ResourceNotFoundException("La " +
                "elección no fue encontrada"));
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!this.electionRepository.existsById(id))
            throw new ResourceNotFoundException("El eleccion a eliminar no existe");
        electionRepository.deleteById(id);
    }

    @Override
    @Transactional
    public void updateAllStatusElection() {
        List<ElectionEntity> elecciones = electionRepository.findAll();
        List<ElectionEntity> updatedElections = elecciones.stream()
                .filter(election -> election.getState() != calcularNuevoEstado(election.getStartDate(), election.getEndDate()))
                .peek(election -> {
                    StateElectionEnum newState = calcularNuevoEstado(election.getStartDate(), election.getEndDate());
                    election.setState(newState);
                    if (newState == StateElectionEnum.INACTIVE) {
                        resultService.countVotes(election);
                    }
                })
                .toList();
        if (!updatedElections.isEmpty()) {
            electionRepository.saveAll(updatedElections);
        }
    }

    private StateElectionEnum calcularNuevoEstado(LocalDate startDate, LocalDate endDate) {
        LocalDate fechaActual = LocalDate.now(ZoneId.of("America/Lima"));
        return fechaActual.isBefore(startDate) ? StateElectionEnum.PENDING :
                fechaActual.isAfter(endDate) ? StateElectionEnum.INACTIVE :
                        StateElectionEnum.ACTIVE;
    }


}
