package com.crymuzz.evotingapispring.service;

import com.crymuzz.evotingapispring.entity.dto.VoteRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.VoteResponseDTO;
import org.web3j.protocol.exceptions.TransactionException;

import java.io.IOException;

public interface IVoteService {
    VoteResponseDTO vote(VoteRegisterDTO voteRegisterDTO) throws IOException, TransactionException;
}
