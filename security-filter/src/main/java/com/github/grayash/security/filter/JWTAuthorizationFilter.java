package com.github.grayash.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.github.grayash.security.filter.constant.SecurityConstants;

import io.jsonwebtoken.Jwts;


public class JWTAuthorizationFilter  extends UsernamePasswordAuthenticationFilter  implements SecurityConstants{
	
	private static final Logger Log = LoggerFactory.getLogger(JWTAuthorizationFilter.class);
	
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
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
        String user = getAuthentication(((HttpServletRequest)req));
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user, null));
        chain.doFilter(req, res);
    }
	
	private String getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            // parse the token.
            String user = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                    .getBody()
                    .getSubject();
            if(Log.isDebugEnabled())
            	Log.debug("User is authorized and customer id is::"+user);
            return user;
        }
        if(Log.isErrorEnabled())
        	Log.error(TOKEN_PREFIX+" token is null");
        return null;
    }
}