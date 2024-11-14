package com.crymuzz.evotingapispring.configuration;

import com.crymuzz.evotingapispring.exception.JWTAuthenticationEntryPoint;
import com.crymuzz.evotingapispring.security.jwt.JWTConfigurer;
import com.crymuzz.evotingapispring.security.jwt.JWTFilter;
import com.crymuzz.evotingapispring.security.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Clase de configuracion para la autorizacion y autenticacion de usuario dentro del sistema
 * Funcion: Bean IoC Spring - Contiene las politicas de acceso, autenticacion con/sin estado, gestion de tokens y
 * codificacion de claves
 * Dependencias: Jwt - Spring Security
 */

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity // Uso de @PreAuthorize
public class WebSecurityConfig {

    private final TokenProvider tokenProvider;
    private final JWTFilter jwtRequestFilter;
    private final JWTAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final UserDetailsService userDetailsService;

    /**
     * Configura la cadena de seguridad para definir politicas de acceso y autenticacion
     *
     * @param http parametro por defecto de la implementacion de la cadena de seguridad
     * @return SecurityFilterChain cotiene las configuraciones establecidas en el metodo
     * @throws Exception exception por algun error en tiempo de ejeccion
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults()) // Habilita el cors default
                .csrf(AbstractHttpConfigurer::disable) // Deshabilita el cors, para aplicaciones con JWT
                .authorizeHttpRequests( // Gestion de accesos y permisos (por verse)
                        auth -> auth
                                .anyRequest().permitAll()
//                                .requestMatchers("/auth/login").permitAll()
//                                .requestMatchers("/auth/register/student").permitAll()
//                                .anyRequest().authenticated()
                )
                .formLogin(AbstractHttpConfigurer::disable) // Desactiva el formulario de inicio de sesión predeterminado
                .exceptionHandling(e -> e.authenticationEntryPoint(jwtAuthenticationEntryPoint)) // Define un manejador para errores de autenticación
                .sessionManagement(h -> h.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // Define la política sin estado para evitar sesiones de usuario
                .with(new JWTConfigurer(tokenProvider), Customizer.withDefaults());  // Configura el uso de JWT en la seguridad
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);  // Agrega el filtro JWT antes del filtro de autenticación
        return http.build();
    }

    /**
     * Gestor de autenticacion
     *
     * @param authenticationConfiguration es el gestor de autenticacion del sistema
     * @return AuthenticationManager obtiene la instancia
     * @throws Exception exception para generales
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Codificacion de claves
     *
     * @return PasswordEncoder para la seguridad
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
