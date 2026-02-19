package com.kabi.apiGw.component;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class UserContextHeaderFilter implements GlobalFilter, Ordered {

    @Override
    public int getOrder() {
        return SecurityWebFiltersOrder.AUTHENTICATION.getOrder() + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .cast(JwtAuthenticationToken.class)
                .flatMap(
                        auth -> {
                            Jwt jwt = auth.getToken();
                            ServerHttpRequest serverHttpRequest =
                                    exchange.getRequest()
                                            .mutate()
                                            .header("X-User-Id", jwt.getClaimAsString("id"))
                                            .header("X-User-Name", jwt.getClaimAsString("name"))
                                            .header("X-User-Handle", jwt.getClaimAsString("name"))
                                            .header("X-User-Email", jwt.getClaimAsString("email"))
                                            .header(
                                                    "X-User-Avatar",
                                                    jwt.getClaimAsString("profile_url"))
                                            .build();

                            return chain.filter(
                                    exchange.mutate().request(serverHttpRequest).build());
                        })
                .onErrorResume(e -> chain.filter(exchange))
                .switchIfEmpty(chain.filter(exchange));
    }
}
