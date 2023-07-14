package com.dehaanido.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@EnableWebSecurity
public class ResourceServerConfig {

    public static final String ROLES_Claim = "roles";

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            Converter<Jwt, Collection<GrantedAuthority>> jwtToAuthorityConverter) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtToAuthorityConverter);

        http.authorizeRequests(authorizeRequests-> {
            authorizeRequests
                    .requestMatchers(HttpMethod.GET, "/v1/customers")
                    .hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/v1/customers").hasRole("ADMIN");
        }).oauth2ResourceServer().jwt();
        return http.build();
    }

    @Bean
    public Converter<Jwt, Collection<GrantedAuthority>> jwtToAuthorityConverter() {

        return new Converter<Jwt, Collection<GrantedAuthority>>() {
            @Override
            public Collection<GrantedAuthority> convert(Jwt jwt) {
                List<String> roles = jwt.getClaimAsStringList(ROLES_Claim);
                if (roles != null) {
                    return roles.stream().map(eachRole -> new SimpleGrantedAuthority(eachRole)).collect(Collectors.toList());
                }
                return Collections.emptyList();
            }
        };
    }
}

