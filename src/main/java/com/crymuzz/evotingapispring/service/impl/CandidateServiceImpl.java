package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.CandidateEntity;
import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.PartyEntity;
import com.crymuzz.evotingapispring.entity.dto.CandidateProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.CandidateRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.CandidateResponseDTO;
import com.crymuzz.evotingapispring.entity.enums.StateElectionEnum;
import com.crymuzz.evotingapispring.exception.BadRequestException;
import com.crymuzz.evotingapispring.exception.ErrorResourceImageException;
import com.crymuzz.evotingapispring.exception.ResourceNotFoundException;
import com.crymuzz.evotingapispring.mapper.CandidateMapper;
import com.crymuzz.evotingapispring.repository.CandidateRepository;
import com.crymuzz.evotingapispring.repository.ElectionRepository;
import com.crymuzz.evotingapispring.repository.PartyRepository;
import com.crymuzz.evotingapispring.service.ICandidateService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CandidateServiceImpl implements ICandidateService {

    private final CandidateRepository candidateRepository;
    private final PartyRepository partyRepository;
    private final ElectionRepository electionRepository;
    private final CandidateMapper candidateMapper;
    private final StorageServiceImpl storageService;

    @Override
    @Transactional
    public CandidateResponseDTO saveCandidate(CandidateRegisterDTO candidateRegisterDTO) {
        String imgPath = storageService.store(candidateRegisterDTO.getImg());
        if (imgPath.isBlank() || imgPath.isEmpty())
            throw new ErrorResourceImageException("Error al guardar la imagen");
        PartyEntity party = partyRepository.findById(candidateRegisterDTO.getPartyId())
                .orElseThrow(() -> new ResourceNotFoundException("El partido especificado no existe"));
        ElectionEntity election = electionRepository.findById(candidateRegisterDTO.getElectionId())
                .orElseThrow(() -> new ResourceNotFoundException("La elección especificada no existe"));
        if (candidateRepository.existsByFirstNameAndLastNameAndElection(candidateRegisterDTO.getFirstName(),
                candidateRegisterDTO.getLastName(), election))
            throw new BadRequestException("El candidato ya existe");
        if (election.getState() != StateElectionEnum.PENDING)
            throw new BadRequestException("No se pueden agregar candidatos, la elección no está en estado pendiente");

        CandidateEntity candidateEntity = candidateMapper.toCandidateEntity(candidateRegisterDTO, party, election);
        candidateEntity.setImage(imgPath);
        CandidateEntity savedCandidate = candidateRepository.save(candidateEntity);
        return candidateMapper.toCandidateResponseDTO(savedCandidate);
    }

    @Override
    @Transactional(readOnly = true)
    public Resource findImgCandidateById(Long id) {
        CandidateEntity candidateEntity = candidateRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("El candidato no existe"));
        String imgPath = candidateEntity.getImage();
        if (imgPath.isEmpty() || imgPath.isBlank())
            throw new ResourceNotFoundException("La imagen del candidato no ha encontrado");
        return storageService.loadSource(imgPath);
    }

    @Override
    @Transactional(readOnly = true)
    public CandidateResponseDTO findById(Long id) {
        CandidateEntity candidate = candidateRepository.findById(id).orElseThrow(IllegalArgumentException::new);
        return candidateMapper.toCandidateResponseDTO(candidate);
    }

    @Override
    @Transactional(readOnly = true)
    public List<CandidateResponseDTO> findAll() {
        return candidateRepository.findAll().stream().map(candidateMapper::toCandidateResponseDTO).toList();
    }

    @Override
    @Transactional(readOnly = true)
    public CandidateProfileDTO getProfile(Long id) {
        CandidateEntity candidateEntity = candidateRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("El candidato no existe"));
        return candidateMapper.toCandidateProfileDTO(candidateEntity);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        this.candidateRepository.deleteById(id);
    }

    @Override
    public List<CandidateResponseDTO> findByElectionId(Long id) {
        return this.candidateRepository.findCandidateEntityByElectionId(id).stream().map(candidateMapper::toCandidateResponseDTO).toList();
    }
}
