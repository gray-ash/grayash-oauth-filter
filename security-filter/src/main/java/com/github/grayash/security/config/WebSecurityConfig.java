package com.github.grayash.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.github.grayash.security.filter.JWTAuthorizationFilter;
import com.github.grayash.security.filter.OauthEntryPoint;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	OauthEntryPoint enrtyPoint() {
		return new OauthEntryPoint();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/v2/api-docs", "/configuration/ui", "/swagger-resources", "/configuration/security",
						"/swagger-ui.html", "/webjars/**", "/app/otp/**", "/manageuser/register", "/manageuser/login")
				.permitAll().anyRequest().authenticated().and()
				.addFilterAfter(new JWTAuthorizationFilter(), BasicAuthenticationFilter.class).httpBasic()
				.authenticationEntryPoint(enrtyPoint());
		;

		http.csrf().disable();
	}
	
	
	
}
