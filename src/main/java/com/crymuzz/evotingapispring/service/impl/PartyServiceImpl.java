package com.crymuzz.evotingapispring.service.impl;

import com.crymuzz.evotingapispring.entity.PartyEntity;
import com.crymuzz.evotingapispring.entity.dto.PartyRegisterDTO;
import com.crymuzz.evotingapispring.entity.dto.PartyResponseDTO;
import com.crymuzz.evotingapispring.exception.BadRequestException;
import com.crymuzz.evotingapispring.exception.ErrorResourceImageException;
import com.crymuzz.evotingapispring.exception.ResourceNotFoundException;
import com.crymuzz.evotingapispring.repository.PartyRepository;
import com.crymuzz.evotingapispring.service.IPartyService;
import com.crymuzz.evotingapispring.mapper.PartyMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PartyServiceImpl implements IPartyService {

    private final PartyRepository partyRepository;
    private final PartyMapper partyMapper;
    private final StorageServiceImpl storageService;

    @Override
    @Transactional
    public PartyResponseDTO saveParty(PartyRegisterDTO partyRegisterDTO) {
        String imgPath = storageService.store(partyRegisterDTO.getImg());
        if (imgPath.isEmpty() || imgPath.isBlank())
            throw new ErrorResourceImageException("Error al guardar el recurso");
        boolean existParty = partyRepository.existsByName(partyRegisterDTO.getName());
        if (existParty)
            throw new BadRequestException("El recurso de partido ya existe");
        PartyEntity partyEntity = partyMapper.toPartyEntity(partyRegisterDTO);
        partyEntity.setImg(imgPath);
        partyEntity = partyRepository.save(partyEntity);
        return partyMapper.toPartyResponse(partyEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public List<PartyResponseDTO> findAll() {
        return partyRepository.findAll().stream().map(partyMapper::toPartyResponse).toList();
    }

    @Override
    @Transactional(readOnly = true)
    public PartyResponseDTO findById(Long id) {
        Optional<PartyEntity> party = partyRepository.findById(id);
        return party.map(partyMapper::toPartyResponse).orElseThrow(IllegalArgumentException::new);
    }

    @Override
    @Transactional(readOnly = true)
    public Resource findImgPartyById(Long id) {
        PartyEntity partyEntity = partyRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("No " +
                "se encontró el partido"));
        String imgPath = partyEntity.getImg();
        if (imgPath.isEmpty() || imgPath.isBlank())
            throw new ErrorResourceImageException("Error al recuperar la imagen del partido");
        return storageService.loadSource(imgPath);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        if (!partyRepository.existsById(id))
            throw new IllegalArgumentException("El partido a eliminar no existe");
        this.partyRepository.deleteById(id);
    }

}
