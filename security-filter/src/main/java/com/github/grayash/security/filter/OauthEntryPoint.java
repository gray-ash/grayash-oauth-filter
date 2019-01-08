package com.github.grayash.security.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

public class OauthEntryPoint extends BasicAuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authEx)
			throws IOException, ServletException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setHeader("Content-Type", "application/json");
		PrintWriter writer = response.getWriter();
		Map output = new HashMap();
		output.put("STATUS", "UNAUTHORIZED");
		output.put("CODE:", "401");
		output.put("MSG:", authEx.getMessage());
		writer.println(constructJsonResponse(output));
	}
	
	
	private String constructJsonResponse(Object object){
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        try {
            return mapper.writeValueAsString(object);
        }catch (Exception e){
            
        }
        return null;

    }
	
	
	@Override
    public void afterPropertiesSet() throws Exception {
        setRealmName("gray-ash");
        super.afterPropertiesSet();
    }

	
}