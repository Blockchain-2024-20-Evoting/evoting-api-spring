package com.crymuzz.evotingapispring.repository;

import com.crymuzz.evotingapispring.entity.ResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ResultRepository extends JpaRepository<ResultEntity, Long> {
    List<ResultEntity> findResultEntityByCandidateEntityElectionId(Long electionId);
}
