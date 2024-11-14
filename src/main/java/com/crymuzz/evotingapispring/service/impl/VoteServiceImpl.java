package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.*;
import com.crymuzz.evotingapispring.entity.dto.TransactionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.TransactionResponseDTO;
import com.crymuzz.evotingapispring.entity.dto.VoteRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.VoteResponseDTO;
import com.crymuzz.evotingapispring.entity.enums.StateElectionEnum;
import com.crymuzz.evotingapispring.exception.ElectionNotFoundException;
import com.crymuzz.evotingapispring.exception.ExcessiveVotesException;
import com.crymuzz.evotingapispring.exception.ResourceNotFoundException;
import com.crymuzz.evotingapispring.mapper.TransactionMapper;
import com.crymuzz.evotingapispring.mapper.VoteMapper;
import com.crymuzz.evotingapispring.repository.*;
import com.crymuzz.evotingapispring.service.IContractVoteService;
import com.crymuzz.evotingapispring.service.IVoteService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class VoteServiceImpl implements IVoteService {

    private final StudentRepository studentRepository;
    private final VoteRepository voteRepository;
    private final CandidateRepository candidateRepository;
    private final IContractVoteService contractVoteService;
    private final TransactionMapper transactionMapper;
    private final TransactionServiceImpl transactionService;
    private final VoteMapper voteMapper;


    @Override
    @Transactional
    public VoteResponseDTO vote(VoteRegisterDTO voteRegisterDTO) throws IOException, TransactionException {

        Long candidateId = voteRegisterDTO.getCandidateId();
        Long studentId = voteRegisterDTO.getStudentId();

        StudentEntity student = studentRepository.findById(studentId)
                .orElseThrow(() -> new ResourceNotFoundException("El estudiante no existe"));

        CandidateEntity candidate = candidateRepository.findById(candidateId)
                .orElseThrow(() -> new ResourceNotFoundException("El candidato no fue encontrado"));

        ElectionEntity election = candidate.getElection();

        // Validar que la elección esté activa
        if (election.getState() != StateElectionEnum.ACTIVE) {
            throw new ElectionNotFoundException("La elección no está activa");
        }

        // Validar que el estudiante no haya votado en esta elección
        if (contractVoteService.hasStudentVoted(election.getId(), student.getId())) {
            throw new ExcessiveVotesException("El estudiante ya ha votado en esta elección");
        }
        TransactionReceipt transaction = contractVoteService.vote(election.getId(), candidate.getId(),
                student.getId());
        TransactionRegisterDTO transactionRegister = transactionMapper.toTransactionRegisterDTO(transaction);
        TransactionResponseDTO response = transactionService.saveTransaction(transactionRegister);
        VoteEntity vote = voteRepository.save(voteMapper.toVoteEntity(response, student));
        return voteMapper.voteResponseDTO(vote);
    }




}
