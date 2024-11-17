package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.PartyEntity;
import com.crymuzz.evotingapispring.entity.dto.PartyRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.PartyResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PartyMapper {

    private final ModelMapper modelMapper;

    public PartyEntity toPartyEntity(PartyRegisterDTO registerDTO) {
        return modelMapper.map(registerDTO, PartyEntity.class);
    }

    public PartyResponseDTO toPartyResponse(PartyEntity partyEntity) {
        return modelMapper.map(partyEntity, PartyResponseDTO.class);
    }

}
