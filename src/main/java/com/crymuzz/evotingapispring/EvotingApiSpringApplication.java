package com.crymuzz.evotingapispring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class EvotingApiSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(EvotingApiSpringApplication.class, args);
    }
}