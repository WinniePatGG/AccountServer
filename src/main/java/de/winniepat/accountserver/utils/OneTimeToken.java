package de.winniepat.accountserver.utils;


import org.springframework.security.crypto.bcrypt.BCrypt;

public record OneTimeToken(String hash, long expiresAt, Object... data) {

    public OneTimeToken(byte[] secret, long expiresAt, Object... data){
        this(BCrypt.hashpw(secret, BCrypt.gensalt()), expiresAt, data);
    }

    public boolean check(String secret) {
        return System.currentTimeMillis() < expiresAt && BCrypt.checkpw(secret, hash);
    }
}
