package com.crymuzz.evotingapispring.repository;

import com.crymuzz.evotingapispring.entity.StudentEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface StudentRepository extends JpaRepository<StudentEntity, Long> {

    boolean existsByFirstNameAndLastName(String firstName, String lastName);

    boolean existsByFirstNameAndLastNameAndUserIdNot(String firstName, String lastName, Long userId);



}
