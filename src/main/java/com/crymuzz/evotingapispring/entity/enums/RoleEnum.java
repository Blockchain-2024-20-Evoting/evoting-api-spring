package com.crymuzz.evotingapispring.entity.enums;

/**
 * Enum que define los posibles roles de un usuario dentro del sistema.
 * <p>
 * Los roles son utilizados para gestionar los permisos y accesos dentro de la aplicación.
 */

public enum RoleEnum {
    // Rol de administrador, tiene acceso a todas las funcionalidades del sistema.
    ADMIN,

    // Rol de estudiante, tiene acceso limitado a funciones relacionadas con la votación.
    STUDENT
}
