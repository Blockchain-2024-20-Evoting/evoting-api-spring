package com.crymuzz.evotingapispring.service;

import com.crymuzz.evotingapispring.entity.dto.AuthResponseDTO;
import com.crymuzz.evotingapispring.entity.dto.LoginDTO;
import com.crymuzz.evotingapispring.entity.dto.UserProfileDTO;
import com.crymuzz.evotingapispring.entity.dto.UserRegisterDTO;

public interface IUserService {

    UserProfileDTO saveStudent(UserRegisterDTO userRegister);
    UserProfileDTO update(Long id, UserProfileDTO userProfile);
    UserProfileDTO findById(Long id);
    // Autenticación
    AuthResponseDTO login(LoginDTO loginDTO);
}
