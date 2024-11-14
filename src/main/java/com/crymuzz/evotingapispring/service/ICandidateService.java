package com.crymuzz.evotingapispring.service;

import com.crymuzz.evotingapispring.entity.dto.CandidateProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.CandidateRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.CandidateResponseDTO;
import org.springframework.core.io.Resource;

import java.util.List;

public interface ICandidateService {
    CandidateResponseDTO saveCandidate(CandidateRegisterDTO candidateRegisterDTO);
    CandidateResponseDTO findById(Long id);
    Resource findImgCandidateById(Long id);
    List<CandidateResponseDTO> findAll();
    CandidateProfileDTO getProfile(Long id);
    void delete(Long id);
    List<CandidateResponseDTO> findByElectionId(Long id);
}
