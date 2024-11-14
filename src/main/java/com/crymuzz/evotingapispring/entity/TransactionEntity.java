package com.crymuzz.evotingapispring.entity;

import com.crymuzz.evotingapispring.entity.enums.TransactionStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "transactions", uniqueConstraints = @UniqueConstraint(columnNames = {"block_number",
        "block_hash"}))
public class TransactionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, name = "transaction_hash", unique = true, updatable = false, length = 66)
    private String transactionHash;

    @Column(nullable = false, name = "block_hash", unique = true, updatable = false, length = 66)
    private String blockHash;

    @Column(nullable = false, name = "block_number", updatable = false)
    private String blockNumber;

    @Column(nullable = false, updatable = false)
    private String status;

    @Enumerated(EnumType.STRING)
    private TransactionStatus transactionStatus;

    @Column(nullable = false, updatable = false, length = 42, name = "from_account")
    private String from;

    @Column(nullable = false, updatable = false, length = 42, name = "to_account")
    private String to;

    @Column(nullable = false, name = "gas_used", updatable = false)
    private String gasUsed;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

}

