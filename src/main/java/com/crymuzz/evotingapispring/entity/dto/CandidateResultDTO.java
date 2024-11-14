package com.crymuzz.evotingapispring.entity.dto;

import lombok.Data;

@Data
public class CandidateResultDTO {
    private Long id;
    private String firstName;
    private String lastName;
    private String partyName;
    private String electionName;
}
