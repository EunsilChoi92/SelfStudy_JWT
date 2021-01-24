package com.pisces.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.pisces.jwt.model.User;
import com.pisces.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUsername(username);
		System.out.println("꺄 : " + userEntity);
		return new PrincipalDetails(userEntity);
	}

}
