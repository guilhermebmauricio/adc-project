package pt.unl.fct.di.adc.firstwebapp.util;

import java.util.UUID;

public class AuthToken {

	public static final long EXPIRATION_TIME = 900L;

	public String tokenId;
	public String username;
	public String role;
	public long issuedAt;
	public long expiresAt;

	public AuthToken() {}

	public AuthToken(String username, String role) {
		this.tokenId = UUID.randomUUID().toString();
		this.username = username;
		this.role = role;
		this.issuedAt = System.currentTimeMillis() / 1000L;
		this.expiresAt = this.issuedAt + EXPIRATION_TIME;
	}

	public boolean hasExpired() {
		return (System.currentTimeMillis() / 1000L) > this.expiresAt;
	}
}