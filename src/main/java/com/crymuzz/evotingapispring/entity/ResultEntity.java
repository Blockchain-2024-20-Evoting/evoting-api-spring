package com.crymuzz.evotingapispring.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import lombok.*;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Table(name = "results")
public class ResultEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "candidate_id", nullable = false)
    private CandidateEntity candidateEntity;

    @Column(name = "count_votes", nullable = false)
    private Long countVotes;

    @Column(nullable = false)
    private double percentages;

    @Column(nullable = false, name = "is_winner")
    private boolean isWinner;

    @Column(name = "party_name", nullable = false)
    private String partyName;

    @Column(name = "election_name", nullable = false)
    private String electionName;


}
