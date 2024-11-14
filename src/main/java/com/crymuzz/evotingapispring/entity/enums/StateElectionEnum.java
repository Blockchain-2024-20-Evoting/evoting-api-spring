package com.crymuzz.evotingapispring.entity.enums;

/**
 * Enum que define los posibles estados de una elección.
 * <p>
 * Este `enum` se utiliza para controlar el flujo de una elección, permitiendo identificar si está pendiente,
 * activa o inactiva.
 */
public enum StateElectionEnum {
    // Estado de la elección cuando aún no ha comenzado o está esperando ser activada.
    PENDING,

    // Estado de la elección cuando está en curso y se puede votar.
    ACTIVE,

    // Estado de la elección cuando ha finalizado o está inactiva, y no se puede votar.
    INACTIVE
}
