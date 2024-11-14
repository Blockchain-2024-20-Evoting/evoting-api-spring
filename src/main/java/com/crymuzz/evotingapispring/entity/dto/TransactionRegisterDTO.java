package com.crymuzz.evotingapispring.entity.dto;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class TransactionRegisterDTO {
    private String transactionHash;
    private String blockHash;
    private String blockNumber;
    private String status;
    private String from;
    private String to;
    private String gasUsed;
}
