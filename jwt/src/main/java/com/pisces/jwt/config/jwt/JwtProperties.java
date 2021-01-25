package com.pisces.jwt.config.jwt;

public interface JwtProperties {
	String SECRET = "pisces"; // 우리 서버만 알고 있는 secret value
	int EXPIRATION_TIME = 60000 * 10;
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";

}
