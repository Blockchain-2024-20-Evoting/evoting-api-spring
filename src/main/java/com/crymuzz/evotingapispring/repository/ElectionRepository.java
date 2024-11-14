package com.crymuzz.evotingapispring.repository;

import com.crymuzz.evotingapispring.entity.ElectionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ElectionRepository extends JpaRepository<ElectionEntity, Long> {
    boolean existsByName(String name);
}
