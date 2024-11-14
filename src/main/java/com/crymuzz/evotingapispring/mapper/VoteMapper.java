package com.crymuzz.evotingapispring.mapper;

import com.crymuzz.evotingapispring.entity.StudentEntity;
import com.crymuzz.evotingapispring.entity.TransactionEntity;
import com.crymuzz.evotingapispring.entity.VoteEntity;
import com.crymuzz.evotingapispring.entity.dto.TransactionResponseDTO;
import com.crymuzz.evotingapispring.entity.dto.VoteResponseDTO;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class VoteMapper {

    private final ModelMapper modelMapper;

    public VoteResponseDTO voteResponseDTO(VoteEntity voteEntity) {
        VoteResponseDTO voteResponseDTO = new VoteResponseDTO();
        voteResponseDTO.setVoteTime(LocalDateTime.now());
        voteResponseDTO.setHashVote(voteEntity.getTransactionEntity().getTransactionHash());
        voteResponseDTO.setMessage(voteEntity.getStudentEntity().getFirstName() + " " + voteEntity.getStudentEntity().getLastName() + " tu voto fue " +
                "registrado " +
                "correctamente!");
        voteResponseDTO.setStatusTransaction(voteEntity.getTransactionEntity().getTransactionStatus().name());
        return voteResponseDTO;
    }

    public VoteEntity toVoteEntity(TransactionResponseDTO transaction, StudentEntity student) {
        VoteEntity voteEntity = new VoteEntity();
        voteEntity.setStudentEntity(student);
        voteEntity.setTransactionEntity(modelMapper.map(transaction, TransactionEntity.class));
        return voteEntity;
    }

}
