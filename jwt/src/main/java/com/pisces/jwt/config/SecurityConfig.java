package com.pisces.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

import com.pisces.jwt.config.jwt.JwtAuthenticationFilter;
import com.pisces.jwt.config.jwt.JwtAuthorizationFilter;
import com.pisces.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Security Filter Chain에 filter 걸기
		// BasicAuthenticationFilter가 실행되기 전에 MyFilter3 실행
		// addFilterAfter를 사용해도 security filter chain이 BasicAuthenticationFilter보다 먼저 실행됨
		// http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class); 
		// BasicAuthenticationFilter가 security filter chain보다 먼저 실행되게 하고 싶으면
		// http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); 
		
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // STATELESS - 세션을 쓰지 않음
		.and()
		.addFilter(corsFilter) // @CrossOrigin(인증X), 시큐리티 필터에 등록해줘야 함(인증O)
		.formLogin().disable() // formLogin disable - form tag를 만들어서 로그인을 하지 않음
		.httpBasic().disable() // httpBasic disable - 기본 인증 방식이 아닌 Bearer Token 사용
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) // UsernamePasswordAuthenticationFilter 등록(formLogin disable 때문에)
		.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))  // (윗 줄 이어서) 그리고 AuthenticationManager를 인자값으로 넘겨줘야 함(WebSecurityConfigurerAdapter가 가지고 있음)
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll();
	}

}
