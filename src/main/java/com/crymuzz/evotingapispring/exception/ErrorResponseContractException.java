package com.crymuzz.evotingapispring.exception;

public class ErrorResponseContractException extends RuntimeException {

    public ErrorResponseContractException(String message) {
        super(message);
    }
}
