package com.crymuzz.evotingapispring.repository;

import com.crymuzz.evotingapispring.entity.RoleEntity;
import com.crymuzz.evotingapispring.entity.enums.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    // Buscar un rol por su nombre
    Optional<RoleEntity> findByName(RoleEnum role);

}
