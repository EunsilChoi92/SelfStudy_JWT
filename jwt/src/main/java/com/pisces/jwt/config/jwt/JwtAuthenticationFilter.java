package com.pisces.jwt.config.jwt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
// /login 요청을 해서 username, password를 post로 전송하면 이 filter가 동작함
// security config에서 formLogin을 disable하면 작동하지 않음
// 그래서 이 filler를 security config에 등록해줘야 함(.addFilter(new JwtAuthenticationFilter())

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationMager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username, password 받아서 
		// 2. 일치하는지 로그인 시도를 해봄
		// 	authenticationManager로 로그인 시돌르 하면 PrincipalDetailsService가 호출됨
		// 	그러면 loadUserByUsername() method가 자동으로 실행됨
		
		// 3. PrincipalDetails를 세션에 담고(세션에 담지 않으면 권한 관리가 안 됨)
		
		// 4. JWT 토큰을 만들어서 응답해주면 됨
		
		return super.attemptAuthentication(request, response);
	}

}
