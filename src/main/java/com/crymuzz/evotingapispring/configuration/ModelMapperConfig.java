package com.crymuzz.evotingapispring.configuration;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Clase de configuracion del modelMapper
 * Funcion: Bean IoC Spring - Contiene el bean para mapear objetos
 */

@Configuration
public class ModelMapperConfig {

    /**
     * @return Retorna la instancia del modelmapper
     */

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

}
