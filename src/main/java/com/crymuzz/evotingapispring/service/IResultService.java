package com.crymuzz.evotingapispring.service;

import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.dto.ResultResponseDTO;

import java.io.IOException;
import java.util.List;

public interface IResultService {
    void countVotes(ElectionEntity electionEntity);
    Long getVotesCandidate(Long candidateId) throws IOException;
    List<ResultResponseDTO> getResultsByElection(Long electionId);
}
