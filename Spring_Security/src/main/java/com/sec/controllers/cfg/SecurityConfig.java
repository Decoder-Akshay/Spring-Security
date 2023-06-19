package com.sec.controllers.cfg;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity

public class SecurityConfig {
	
	@Bean
	public PasswordEncoder passwordEncode() {
		
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetail() {
		
		UserDetails normaluser= User
				.withUsername("akshay")
				.password(passwordEncode().encode("password"))
				.roles("NORMAL")
				.build();
		
		UserDetails adminuser= User
				.withUsername("akshay1")
				.password(passwordEncode().encode("password1"))
				.roles("ADMIN")
				.build();
		
		InMemoryUserDetailsManager imdm= new InMemoryUserDetailsManager(normaluser,adminuser);
		return imdm;
		
		
		//for checking with names and sending names to database methods
//		return new CustomUserDetailService();
	}
	
	
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable()
		.authorizeHttpRequests()
		
		.requestMatchers("/home/admin")
		.hasRole("ADMIN")
		.requestMatchers("/home/normal")
		.hasRole("NORMAL")
		
		
		.requestMatchers("/home/public")
		.permitAll()
		.anyRequest()
		.authenticated()
		.and()
		.formLogin();
		return http.build();
	}

}
