package com.crymuzz.evotingapispring.entity.dto;

import com.crymuzz.evotingapispring.entity.enums.TransactionStatus;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class TransactionResponseDTO {
    private Long id;
    private String transactionHash;
    private String blockHash;
    private String blockNumber;
    private String status;
    private TransactionStatus transactionStatus;
    private String from;
    private String to;
    private String gasUsed;
    private LocalDateTime createdAt;
}
