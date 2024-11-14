package com.crymuzz.evotingapispring.service;


import com.crymuzz.evotingapispring.entity.dto.TransactionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.TransactionResponseDTO;

import java.util.List;

public interface ITransactionService {
    TransactionResponseDTO saveTransaction(TransactionRegisterDTO transactionRegisterDTO);
    List<TransactionResponseDTO> findAllTransactions();
    TransactionResponseDTO findTransactionByHash(String hash);
}
