package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.TransactionEntity;
import com.crymuzz.evotingapispring.entity.dto.TransactionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.TransactionResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;
import org.web3j.protocol.core.methods.response.TransactionReceipt;

@Component
@RequiredArgsConstructor
public class TransactionMapper {

    private final ModelMapper modelMapper;

    public TransactionEntity toTransactionEntity(TransactionRegisterDTO transactionRegisterDTO) {
        return modelMapper.map(transactionRegisterDTO, TransactionEntity.class);
    }

    public TransactionRegisterDTO toTransactionRegisterDTO(TransactionReceipt transactionReceipt) {
        return modelMapper.map(transactionReceipt, TransactionRegisterDTO.class);
    }

    public TransactionResponseDTO toTransactionResponseDTO(TransactionEntity transactionEntity) {
        return modelMapper.map(transactionEntity, TransactionResponseDTO.class);
    }

}
