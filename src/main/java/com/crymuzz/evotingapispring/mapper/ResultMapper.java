package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.ResultEntity;
import com.crymuzz.evotingapispring.entity.dto.ResultResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ResultMapper {

    private final ModelMapper modelMapper;

    public ResultResponseDTO toResultResponseDTO(ResultEntity resultEntity) {

        return ResultResponseDTO.builder()
                .id(resultEntity.getId())
                .candidateEntity(resultEntity.getCandidateEntity())
                .countVotes(resultEntity.getCountVotes())
                .percentages(resultEntity.getPercentages())
                .isWinner(resultEntity.isWinner())
                .partyName(resultEntity.getPartyName())
                .electionName(resultEntity.getElectionName())
                .build();
    }
}
