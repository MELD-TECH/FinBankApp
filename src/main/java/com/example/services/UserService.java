package com.example.services;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.config.oauth.TokenManager;
import com.example.model.ChangePassword;
import com.example.model.ResponseResult;
import com.example.model.LoginDTO;
import com.example.model.LoginMessage;
import com.example.model.Role;
import com.example.model.UserInfo;
import com.example.repository.UserInfoRepository;

@Service
public class UserService{

	@Autowired
	private UserInfoRepository repo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authmanager;

	@Autowired
	private TokenManager tokenManager;
	
	@Autowired
	private UserDetailsService userdet;
	
	@Autowired
	private SecurityUtil util;
	
	Logger log = LoggerFactory.getLogger(UserService.class);
	
	public Collection<UserInfo> getUsers(){

		return repo.findAll();
	}
	
	public UserInfo createUser(UserInfo user) {
		log.info("Get user details to be saved ...");
		
		user.setPassword(passwordEncoder.encode(user.getPassword()));	
		
		user.setRole(Role.USER);
		UserInfo us = repo.save(user);
		
		log.info("User created successfully", us);
		return us;
	}
	
	public UserInfo updateUser(UUID id, UserInfo user) {
		Optional<UserInfo> useropt = repo.findById(id);
		
		UserInfo us = new UserInfo();
		
		if(useropt.isPresent()) {
			us = useropt.get();			
			us.setFirstname(user.getFirstname());
			us.setGender(user.getGender());
			us.setLastname(us.getLastname());			
		}
		
		us = repo.save(us);
		log.info("User updated successfully", us);
		
		return us;
	}
	
	public void removeUser(UUID id) {
		repo.deleteById(id);
		log.info("User removed successfully");
	}
	
	public UserInfo findUserById(UUID id) {
		return repo.findById(id).get();
	}
	
	
	public LoginMessage findLoggedOnUser(LoginDTO logindto) throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException{
	
		LoginMessage loginMessage = new LoginMessage();
		
        UserInfo info = repo.findByEmail(logindto.getEmail());
		
		String token = null;
		
        String iv = SecurityUtil.generateKeys();
		
		if(iv.length() < 16) {
					
			iv = SecurityUtil.generateKeys();
			
		}
		
		if(info != null) {
			
			try {
				Authentication auth = authmanager.authenticate(
                  new UsernamePasswordAuthenticationToken(info.getEmail(), info.getPassword()));
			
			SecurityContextHolder.getContext().setAuthentication(auth);
			}catch(AuthenticationException e) {
				e.getMessage();
			}
			
			UserDetails userdetails = userdet.loadUserByUsername(info.getEmail());
			
			token = tokenManager.generateToken(userdetails);
			
			String subject = tokenManager.getUsernameFromToken(token);
			
			Date expiryDate = tokenManager.getExpiryDate(token);
			
			//encrypt the password process 
			String myencpassword = "frankofurt@123456789345678123457";
			
			String algorithm = "AES/CBC/PKCS5Padding";
			
			IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
			
			SecretKey keyspec = new SecretKeySpec(myencpassword.getBytes(), "AES");
			
			String cipherText = util.encrypt(algorithm, userdetails.getPassword(), keyspec, ivspec);
	
//			String decodedText = util.decrypt(algorithm, cipherText, keyspec, ivspec);

			loginMessage.setToken(token);
			loginMessage.setSubject(subject);
			loginMessage.setExpiry(expiryDate);
			loginMessage.setPassencrypt(cipherText);
			loginMessage.setIvparameter(iv);
			loginMessage.setMessage("Success");
			
			return loginMessage;
		}else {
			loginMessage.setToken("TOKEN_NOT_FOUND");
			loginMessage.setMessage("Bad-Credentials");
			return loginMessage;
		}
		
		
		
	}
	
	public ResponseResult changePassword(ChangePassword changePassword) {
		
		ResponseResult result = new ResponseResult();
		
		UserInfo userinfo = null;
		try {
			userinfo = repo.findByEmail(changePassword.getEmail());
			
			if(userinfo != null) {
				String dbpass = userinfo.getPassword();
				
				String currentpassword = changePassword.getCurrentPassword();

				boolean validate = passwordEncoder.matches(currentpassword, dbpass);

				
				if(validate) {

						userinfo.setPassword(passwordEncoder.encode(changePassword.getNewPassword()));
						System.out.println("Password encoded successfully");
						
						repo.save(userinfo);
												
					    result.setMessage("Success");
				}else {
					result.setMessage("Bad-Credentials");
				}
			}
			
		}catch(Exception e){
			throw new BadCredentialsException(e.getMessage());
		}

		
		return result;
	}
		
}
