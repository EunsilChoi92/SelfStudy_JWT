package com.pisces.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pisces.jwt.config.auth.PrincipalDetails;
import com.pisces.jwt.model.User;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있음
// /login 요청을 해서 username, password를 post로 전송하면 이 filter가 동작함
// security config에서 formLogin을 disable하면 작동하지 않음
// 그래서 이 filler를 security config에 등록해줘야 함(.addFilter(new JwtAuthenticationFilter())

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username, password 받아서 
		try {
			/*
			BufferedReader br = request.getReader();
			
			String input = null;
			
			while((input = br.readLine()) != null) {
				System.out.println(input);
			}
			*/
			
			ObjectMapper om = new ObjectMapper(); // Json data를 java object로 변경
			User user = om.readValue(request.getInputStream(), User.class); // User object에 담아줌
			System.out.println(user);
			
			// 토큰 만들기(formLogin을 사용하면 자동으로 만들어줌)
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// PrincipalDetailsService의 loadUserByUsername() method가 실행된 후 정상이면 authentication이 return됨
			// authentication에는 내가 로그인한 정보가 담김
			// authentication은 authenticationToken을 통해 임시로 만든 것
			// DB에 있는 username과 password가 일치함
			Authentication authentication = 
					authenticationManager.authenticate(authenticationToken);
			
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			// 값이 있으면 로그인이 정상적으로 되었다는 뜻
			System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());
			
			// authentication 객체를 session 영역에 저장을 해야함, return을 해줘야 그것이 가능함
			// return의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것
			// 굳이 JWT 토큰을 사용하면 session을 만들 이유가 없으나 단지 권한 처리 떄문에 session에 넣어줌
			return authentication;
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("==============================================");
		
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 seccessfulAuthentication method가 실행됨
	// JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
	// 인증이 정상적으로 되지 않았으면 이 method는 실행되지 않음
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻");
		super.successfulAuthentication(request, response, chain, authResult);
	}

}
