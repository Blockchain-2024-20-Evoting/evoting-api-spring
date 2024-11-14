package com.crymuzz.evotingapispring.service;

import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.dto.ElectionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.ElectionResponseDTO;

import java.util.List;

public interface IElectionService {
    ElectionResponseDTO saveElection(ElectionRegisterDTO electionDTO);
    List<ElectionResponseDTO> findAll();
    ElectionResponseDTO findById(Long id);
    void delete(Long id);
    void updateAllStatusElection();
}
