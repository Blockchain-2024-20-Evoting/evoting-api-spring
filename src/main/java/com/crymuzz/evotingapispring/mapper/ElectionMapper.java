package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.ElectionEntity;
import com.crymuzz.evotingapispring.entity.dto.ElectionRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.ElectionResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ElectionMapper {

    private final ModelMapper modelMapper;

    public ElectionEntity toElectionEntity(ElectionRegisterDTO createDTO) {
        return this.modelMapper.map(createDTO, ElectionEntity.class);
    }

    public ElectionResponseDTO toElectionResponse(ElectionEntity entity) {
        return this.modelMapper.map(entity, ElectionResponseDTO.class);
    }


}
