package com.crymuzz.evotingapispring.service;

import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.exceptions.TransactionException;

import java.io.IOException;
import java.math.BigInteger;

public interface IContractVoteService {
    TransactionReceipt vote(Long electionId, Long candidateId, Long studentId) throws TransactionException, IOException;

    BigInteger getVotes(Long electionId, Long candidateId) throws IOException;

    Boolean hasStudentVoted(Long electionId, Long studentId) throws IOException;
}
