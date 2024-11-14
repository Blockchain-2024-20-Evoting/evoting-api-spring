package com.crymuzz.evotingapispring.exception;

public class ErrorTransactionException extends RuntimeException {

    public ErrorTransactionException(String message) {
        super(message);
    }

}
