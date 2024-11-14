package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.UserEntity;
import com.crymuzz.evotingapispring.entity.dto.AuthResponseDTO;
import com.crymuzz.evotingapispring.entity.dto.LoginDTO;
import com.crymuzz.evotingapispring.entity.dto.UserProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.UserRegisterDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserMapper {

    private final ModelMapper modelMapper;

    public UserEntity toUserEntity(UserRegisterDTO userRegisterDTO) {
        return modelMapper.map(userRegisterDTO, UserEntity.class);
    }

    public UserProfileDTO toUserProfileDTO(UserEntity userEntity) {
        // Configurar manualmente el mapeo para student y role
        modelMapper.typeMap(UserEntity.class, UserProfileDTO.class).addMappings(mapper -> {
            mapper.map(src -> src.getStudent().getFirstName(), UserProfileDTO::setFirstName);
            mapper.map(src -> src.getStudent().getLastName(), UserProfileDTO::setLastName);
            mapper.map(src -> src.getRole().getName(), UserProfileDTO::setRole);
        });
        return modelMapper.map(userEntity, UserProfileDTO.class);
    }

    public UserEntity toUserEntity(LoginDTO loginDTO) {
        return modelMapper.map(loginDTO, UserEntity.class);
    }

    public AuthResponseDTO toAuthResponseDTO(UserEntity userEntity, String token) {
        AuthResponseDTO authResponseDTO = new AuthResponseDTO();
        authResponseDTO.setToken(token);
        authResponseDTO.setRole(userEntity.getRole().getName().name());
        authResponseDTO.setId(userEntity.getId());
        if (userEntity.getStudent() != null) {
            authResponseDTO.setStudentId(userEntity.getStudent().getId());
            authResponseDTO.setFirstName(userEntity.getStudent().getFirstName());
            authResponseDTO.setLastName(userEntity.getStudent().getLastName());
        }
        return authResponseDTO;
    }

}
