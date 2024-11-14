package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.CandidateEntity;
import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.PartyEntity;
import com.crymuzz.evotingapispring.entity.dto.*;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CandidateMapper {

    private final ModelMapper modelMapper;

    public CandidateEntity toCandidateEntity(CandidateRegisterDTO candidateRegisterDTO, PartyEntity party,
                                             ElectionEntity election) {
        CandidateEntity candidate = new CandidateEntity();
        candidate.setFirstName(candidateRegisterDTO.getFirstName());
        candidate.setLastName(candidateRegisterDTO.getLastName());
        candidate.setParty(party);
        candidate.setElection(election);
        return candidate;
    }

    public CandidateResponseDTO toCandidateResponseDTO(CandidateEntity candidateEntity) {
        CandidateResponseDTO candidateResponseDTO = new CandidateResponseDTO();
        candidateResponseDTO.setId(candidateEntity.getId());
        candidateResponseDTO.setFirstName(candidateEntity.getFirstName());
        candidateResponseDTO.setLastName(candidateEntity.getLastName());
        candidateResponseDTO.setImage(candidateEntity.getImage());
        candidateResponseDTO.setPartyName(candidateEntity.getParty().getName());
        candidateResponseDTO.setElectionName(candidateEntity.getElection().getName());
        return candidateResponseDTO;
    }

    public CandidateProfileDTO toCandidateProfileDTO(CandidateEntity candidateEntity) {
        CandidateProfileDTO candidateProfileDTO = modelMapper.map(candidateEntity, CandidateProfileDTO.class);
        candidateProfileDTO.setElection(modelMapper.map(candidateEntity.getElection(), ElectionResponseDTO.class));
        candidateProfileDTO.setParty(modelMapper.map(candidateEntity.getParty(), PartyResponseDTO.class));
        return candidateProfileDTO;
    }


}
