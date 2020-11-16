package com.tcs.tatachem.tsds.utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
 

@Component
public class CorsFilter implements Filter {
	
 @Value("${allowed.origin.list}")
 private String allowedOriginList;
 
 @Value("${spring.profiles.active}")
 private String springProfilesActive;

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    HttpServletResponse response = (HttpServletResponse) res;
    HttpServletRequest request =  (HttpServletRequest) req;
   	List<String> restrictedOrigins = Arrays.asList(allowedOriginList.split(","));
 	String origin = request.getHeader("x-forwarded-host");
 	
	if(!springProfilesActive.equalsIgnoreCase("local"))
   	{
   		if(origin == null || (!restrictedOrigins.contains(origin))) {
   			response.sendError(401, "CORS error : Invalid Request");
   			return;
   		}
   	}
	
     response.setHeader("Access-Control-Allow-Origin", "*");
    response.setHeader("Access-Control-Max-Age", "3600");
    response.setHeader("Access-Control-Allow-Headers",
        "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
    response.setHeader("Access-Control-Allow-Methods", "HEAD, PATCH, POST, PUT, GET, OPTIONS, DELETE");
    chain.doFilter(req, response);
  }

  @Override
  public void init(FilterConfig filterConfig) {
    // Do nothing
  }

  @Override
  public void destroy() {
    // Do nothing
  }

}
