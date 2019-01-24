package com.grayash.security.filter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.grayash.security.filter.constant.SecurityConstants;


public class JWTAuthorizationFilter  extends UsernamePasswordAuthenticationFilter  implements SecurityConstants{
	
	private static final Logger Log = LoggerFactory.getLogger(JWTAuthorizationFilter.class);
	
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(null);
        String header = ((HttpServletRequest)req).getHeader(HEADER_STRING);
        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
        	if(Log.isErrorEnabled()) {
        		Log.error(TOKEN_PREFIX+ " token not present in header");
        	}
            chain.doFilter(req, res);
            return;
        }
        if(Log.isInfoEnabled()) {
    		Log.info(TOKEN_PREFIX+ " token present in header");
    	}
        JSONObject body = getAuthentication(((HttpServletRequest)req));
        try {
        	if(body==null || body.getString("ROLE")==null || !body.getString("ROLE").equals("CUSTOMER")) {
            	throw new Exception();
            }else {
            	SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(body.getString("CSID"), header, getAuthority()));
            }
		} catch (Exception e) {
			if(Log.isErrorEnabled())
            	Log.error("Access denied for the Customer ID or ROLE");
		}
        
        
        chain.doFilter(req, res);
    }
	
	private JSONObject getAuthentication(HttpServletRequest request)  {
        String token = request.getHeader(HEADER_STRING);
        if(Log.isDebugEnabled())
        	Log.debug("Token inside JWTAuthorizationFilter::"+token);
        if (token != null) {
        	token = token.replace(TOKEN_PREFIX, "");
        	String[] split_string = token.split("\\.");
            String base64EncodedHeader = split_string[0];
            String base64EncodedBody = split_string[1];
            String base64EncodedSignature = split_string[2];
            Base64 base64Url = new Base64(true);
            String header = new String(base64Url.decode(base64EncodedHeader));
            String body = new String(base64Url.decode(base64EncodedBody));
            JSONObject json=null;
            try {
            	json = new JSONObject(body);
            	if(Log.isDebugEnabled())
                	Log.debug("Token body::"+json);
            	
			} catch (Exception e) {
				return null;
			}
            if(Log.isDebugEnabled())
            	Log.debug("User is authorized and customer id is::"+body);
            return json;
        }
        if(Log.isErrorEnabled())
        	Log.error(TOKEN_PREFIX+" token is null");
        return null;
    }
	
	
	private List<SimpleGrantedAuthority> getAuthority() {
		return Collections.emptyList();
	}
}