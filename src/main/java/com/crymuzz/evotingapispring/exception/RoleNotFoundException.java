package com.crymuzz.evotingapispring.exception;

public class RoleNotFoundException extends RuntimeException {
    public RoleNotFoundException() {
        super("Rol exception");
    }
}
