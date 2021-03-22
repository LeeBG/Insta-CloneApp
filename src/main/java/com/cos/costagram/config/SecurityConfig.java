package com.cos.costagram.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Bean
	public BCryptPasswordEncoder encode() {
		return new BCryptPasswordEncoder();
	}
	
	//모델 : Image,User,Likes,Follow,Tag		: 다 로그인이 필요함
	//auth는 모델이 아님
	//static 폴더의 이미지에 접근하려 하는데
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.csrf().disable();
		http.authorizeRequests().antMatchers("/","/user/**","/image/**","/follow/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
		.anyRequest()
		.permitAll()
		.and()
		.formLogin()
		.loginPage("/auth/loginForm")
		.loginProcessingUrl("/");
		//OAuth2.0과 CORS는 나중에
//		http.cors().disable();	//자바스크립트에 POST접근 막고 GET접근 막고...등등
//		//컨트롤러에 CrossOrigin를 붙여도 시큐리티에서 막힘
//		//나중에 따로 Security
	}
}
