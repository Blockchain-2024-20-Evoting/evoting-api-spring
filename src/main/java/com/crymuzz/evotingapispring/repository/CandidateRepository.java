package com.crymuzz.evotingapispring.repository;

import com.crymuzz.evotingapispring.entity.CandidateEntity;
import com.crymuzz.evotingapispring.entity.ElectionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CandidateRepository extends JpaRepository<CandidateEntity, Long> {
    boolean existsByFirstNameAndLastNameAndElection(String firstName, String lastName, ElectionEntity election);
    List<CandidateEntity> findByElection(ElectionEntity election);
    List<CandidateEntity> findCandidateEntityByElectionId(Long electionID);
}

