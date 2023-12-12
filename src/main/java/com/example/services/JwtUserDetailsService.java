package com.example.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.example.model.UserInfo;
import com.example.repository.UserInfoRepository;


public class JwtUserDetailsService implements UserDetailsService {

	@Autowired
	private UserInfoRepository sourcerep;

	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		
           UserInfo user = sourcerep.findByEmail(username);
		
		
		UserDetails detail = User.builder().username(user.getEmail())
				.password(user.getPassword())
				.roles(user.getRole().toString())						
				.build();
		
		
		return detail;
	}

}
