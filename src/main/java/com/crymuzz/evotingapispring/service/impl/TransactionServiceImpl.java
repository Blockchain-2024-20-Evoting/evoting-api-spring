package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.TransactionEntity;
import com.crymuzz.evotingapispring.entity.dto.TransactionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.TransactionResponseDTO;
import com.crymuzz.evotingapispring.entity.enums.TransactionStatus;
import com.crymuzz.evotingapispring.exception.BadRequestException;
import com.crymuzz.evotingapispring.exception.ResourceNotFoundException;
import com.crymuzz.evotingapispring.mapper.TransactionMapper;
import com.crymuzz.evotingapispring.repository.TransactionRepository;
import com.crymuzz.evotingapispring.service.ITransactionService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TransactionServiceImpl implements ITransactionService {

    private final TransactionRepository transactionRepository;
    private final TransactionMapper transactionMapper;

    @Override
    public TransactionResponseDTO saveTransaction(TransactionRegisterDTO transactionRegisterDTO) {
        if (transactionRegisterDTO != null) {
            TransactionEntity transaction = transactionMapper.toTransactionEntity(transactionRegisterDTO);
            if (transactionRegisterDTO.getStatus().equals("0x1"))
                transaction.setTransactionStatus(TransactionStatus.SUCCESS);
            else
                transaction.setTransactionStatus(TransactionStatus.FAILED);
            return transactionMapper.toTransactionResponseDTO(transactionRepository.save(transaction));
        }
        throw new BadRequestException("Transacción no completada: " + TransactionStatus.FAILED.name());
    }

    @Override
    public List<TransactionResponseDTO> findAllTransactions() {
        return transactionRepository.findAll().stream().map(transactionMapper::toTransactionResponseDTO).toList();
    }

    @Override
    public TransactionResponseDTO findTransactionByHash(String hash) {
        TransactionEntity transaction =
                transactionRepository.findByTransactionHash(hash).orElseThrow(() -> new ResourceNotFoundException(
                        "Transacción no encontrada"));
        return transactionMapper.toTransactionResponseDTO(transaction);
    }
}
