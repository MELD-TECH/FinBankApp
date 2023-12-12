package com.example.model;

import java.io.Serializable;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Data
@AllArgsConstructor
public class LoginMessage implements Serializable {

	private static final long serialVersionUID = -54394509760560222L;
	
	private String token;
	
	private String subject;
	
	private Date expiry;
	
	private String passencrypt;
	
	private String message;
	
	private String ivparameter;
}
