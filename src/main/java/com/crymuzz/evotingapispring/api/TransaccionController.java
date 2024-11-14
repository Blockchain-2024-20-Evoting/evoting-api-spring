package com.crymuzz.evotingapispring.api;

import com.crymuzz.evotingapispring.entity.dto.TransactionResponseDTO;
import com.crymuzz.evotingapispring.service.ITransactionService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/transactions")
@Tag(name = "Transacciones", description = "Endpoint para las consultas de las transacciones")
@RequiredArgsConstructor
public class TransaccionController {

    private final ITransactionService transactionService;

    @GetMapping("/{hash}")
    public ResponseEntity<TransactionResponseDTO> getTransactionByHash(@PathVariable String hash) {
        TransactionResponseDTO response = transactionService.findTransactionByHash(hash);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity<List<TransactionResponseDTO>> getAllTransactions() {
        List<TransactionResponseDTO> transactions = transactionService.findAllTransactions();
        return new ResponseEntity<>(transactions, HttpStatus.OK);
    }

}
