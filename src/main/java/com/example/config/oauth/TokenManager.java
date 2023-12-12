package com.example.config.oauth;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;

//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.JwtParser;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;

@Component
public class TokenManager {

	
	@Autowired
	private JwtEncoder jwtEncoders;
	
	public String generateToken(UserDetails userdetails) {
		
		Instant time = Instant.now();
		
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.subject(userdetails.getUsername())
				.issuedAt(time)
				.expiresAt(time.plus(10, ChronoUnit.HOURS))
				.issuer("self")
				.build()
				;
				
		return jwtEncoders.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}
	
	public String getUsernameFromToken(String token) {
		JWSObject jwsObject;
		
		JWTClaimsSet claims;
		
		try {
			jwsObject = JWSObject.parse(token);
			
			claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
			
			return claims.getSubject();
		}catch(ParseException e) {
			throw new BadCredentialsException(e.getMessage());
		}
	}
	
	public Date getExpiryDate(String token) {
		JWSObject jwsObject;
		
		JWTClaimsSet claims;
		
		try {
			jwsObject = JWSObject.parse(token);
			
			claims = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
			
			return claims.getExpirationTime();
		}catch(ParseException e) {
			throw new BadCredentialsException(e.getMessage());
		}
	}
	
}
