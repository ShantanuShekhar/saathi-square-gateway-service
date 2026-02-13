package com.saathisquare.getway.filter;

import io.jsonwebtoken.Claims;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.saathisquare.getway.util.JwtUtil;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
	    String path = exchange.getRequest().getURI().getPath();
	    String method = exchange.getRequest().getMethod().name();

	    // Allow OPTIONS requests (CORS preflight) to pass through
	    if ("OPTIONS".equals(method)) {
	        return chain.filter(exchange);
	    }

	    // Allow public endpoints
	    // Allow all public endpoints under /auth and /society
	    if (path.startsWith("/auth/") || path.equals("/auth")
	        || path.startsWith("/society") || path.equals("/society")) {
	        return chain.filter(exchange);
	    }

	    String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
	    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
	        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
	        return exchange.getResponse().setComplete();
	    }

	    String token = authHeader.substring(7);
	    try {
	        Claims claims = JwtUtil.validateToken(token);
	        exchange.getRequest().mutate()
	            .header("X-User-Id", claims.getSubject())
	            .header("X-User-Roles", claims.get("roles").toString());
	    } catch (Exception e) {
	        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
	        return exchange.getResponse().setComplete();
	    }

	    return chain.filter(exchange);
	}

	@Override
	public int getOrder() {
		// Set order to run after CORS filter (higher number = lower priority)
		// CORS filter typically runs at -100, so we run at 0
		return 0;
	}


}
