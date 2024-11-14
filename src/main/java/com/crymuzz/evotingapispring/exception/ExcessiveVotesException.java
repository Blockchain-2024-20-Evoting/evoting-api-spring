package com.crymuzz.evotingapispring.exception;

public class ExcessiveVotesException extends RuntimeException {

    public ExcessiveVotesException(String message) {
        super(message);
    }
}
