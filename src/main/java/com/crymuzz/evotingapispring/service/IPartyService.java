package com.crymuzz.evotingapispring.service;

import com.crymuzz.evotingapispring.entity.dto.PartyRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.PartyResponseDTO;
import org.springframework.core.io.Resource;
import java.util.List;

public interface IPartyService {
    PartyResponseDTO saveParty(PartyRegisterDTO partyRegisterDT);
    List<PartyResponseDTO> findAll();
    PartyResponseDTO findById(Long id);
    Resource findImgPartyById(Long id);
    void delete(Long id);
}
