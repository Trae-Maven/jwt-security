package io.github.trae.jwtsecurity.data.interfaces;

public interface IRefreshToken {

    boolean verify(final String token);
}