package com.kabi.apiGw.component;

import org.springframework.http.HttpCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class CookieJwtConverter implements ServerAuthenticationConverter {
    private static final String COOKIE_NAME = "ac_token";
    private final ServerBearerTokenAuthenticationConverter converter =
            new ServerBearerTokenAuthenticationConverter();

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(COOKIE_NAME);

        if (cookie != null) {
            exchange =
                    exchange.mutate()
                            .request(r -> r.headers(h -> h.setBearerAuth(cookie.getValue())))
                            .build();
        }

        return converter.convert(exchange);
    }
}
