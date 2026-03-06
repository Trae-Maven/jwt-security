package io.github.trae.jwtsecurity.data;

import io.github.trae.jwtsecurity.data.interfaces.IRefreshToken;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class RefreshToken implements IRefreshToken {

    private String tokenHash;
    private long expireAt;

    @Override
    public boolean verify(final String token) {
//        return UtilHash.verify("SHA-512", token, this.getTokenHash());
        return true;
    }
}