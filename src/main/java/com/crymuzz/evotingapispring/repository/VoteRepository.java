package com.crymuzz.evotingapispring.repository;


import com.crymuzz.evotingapispring.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface VoteRepository extends JpaRepository<VoteEntity, Long> {

}
