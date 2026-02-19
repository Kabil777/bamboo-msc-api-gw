package com.kabi.apiGw.config;

import com.kabi.apiGw.component.CookieJwtConverter;
import com.kabi.apiGw.handler.CorsAccessDeniedHandler;
import com.kabi.apiGw.handler.CorsAuthenticationEntryPoint;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@EnableWebFluxSecurity
@Configuration
public class WebSecurityConfig {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of("http://localhost:3000"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsWebFilter(source);
    }

    @Bean
    @Order(1)
    SecurityWebFilterChain authChain(ServerHttpSecurity http) {
        return http.securityMatcher(
                        ServerWebExchangeMatchers.pathMatchers(
                                "/api/v1/auth/**", "/login/oauth2/**"))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex.anyExchange().permitAll())
                .build();
    }

    @Bean
    @Order(2)
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity serverHttpSecurity) {
        return serverHttpSecurity
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(
                        req ->
                                req.pathMatchers(HttpMethod.OPTIONS, "/**")
                                        .permitAll()
                                        .anyExchange()
                                        .authenticated())
                .exceptionHandling(
                        ex ->
                                ex.accessDeniedHandler(new CorsAccessDeniedHandler())
                                        .authenticationEntryPoint(
                                                new CorsAuthenticationEntryPoint()))
                .oauth2ResourceServer(
                        oauth ->
                                oauth.bearerTokenConverter(new CookieJwtConverter())
                                        .jwt(Customizer.withDefaults()))
                .build();
    }
}
