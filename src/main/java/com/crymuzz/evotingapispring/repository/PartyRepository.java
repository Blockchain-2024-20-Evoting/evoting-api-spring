package com.crymuzz.evotingapispring.repository;

import com.crymuzz.evotingapispring.entity.PartyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PartyRepository extends JpaRepository<PartyEntity, Long> {
    boolean existsByName(String name);
}
