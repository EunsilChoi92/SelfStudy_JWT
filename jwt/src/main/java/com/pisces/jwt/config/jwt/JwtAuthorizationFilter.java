package com.pisces.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.pisces.jwt.config.auth.PrincipalDetails;
import com.pisces.jwt.model.User;
import com.pisces.jwt.repository.UserRepository;

// 인증 요청이 있을 때 동작하는 것이 아니라 security가 filter를 가지고 있는데 그 filter 중에서 BasicAuthenticationFilter라는 것이 있음
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 filter를 무조건 거치게 되어 있음
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 filter를 거치지 않음
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	// 인증이나 권한이 필요한 주소 요청이 있을 때 해당 filter가 실행됨
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("인증이나 권한이 필요한 주소가 요청됨");
		
		String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
		System.out.println("jwtHeader : " + jwtHeader);

		// header가 제대로 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
		String jwtToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();
		
		// 서명이 정상적으로 됨
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			// Authentication 객체가 실제로 로그인을 해서 만들어진 것이 아니라 JWT 토큰 서명을 통해 서명이 정상이면 만들어짐
			Authentication authentication = 
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			
			// 강제로 security의 세션에 접근하여 Authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		
		chain.doFilter(request, response);
	}
	
	

}
