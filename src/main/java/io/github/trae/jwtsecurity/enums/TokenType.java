package io.github.trae.jwtsecurity.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.Duration;

@AllArgsConstructor
@Getter
public enum TokenType {

    ACCESS_TOKEN("accessToken", Duration.ofMinutes(20)),
    REFRESH_TOKEN("refreshToken", Duration.ofDays(14));

    private final String key;
    private final Duration expiration;
}