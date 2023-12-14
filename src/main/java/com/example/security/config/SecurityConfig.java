package com.example.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter.HeaderValue;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	@Autowired
	private SecurityProperties securityProperties;




	@Autowired
	AuthenticationConfiguration configuration;

	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	@Order(1)
	SecurityFilterChain configure(final HttpSecurity http) throws Exception {


		http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
				.csrf(AbstractHttpConfigurer::disable)
				.headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer
						.frameOptions(frameOptionsConfig -> frameOptionsConfig.disable())
						.httpStrictTransportSecurity(t -> t.maxAgeInSeconds(31536000))
						.xssProtection(xss -> xss.headerValue(HeaderValue.ENABLED_MODE_BLOCK))
						.contentSecurityPolicy(cps -> cps.policyDirectives("default-src 'self'; object-src 'none'; script-src 'none'; frame-ancestors 'none'; style-src 'self'")))
						.securityMatcher("/api/**")
						.authorizeHttpRequests(auth -> auth.requestMatchers("/api/**").authenticated())
						.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}

	public CorsConfigurationSource corsConfigurationSource() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/api/**", securityProperties.getCorsConfiguration());
		return source;
	}
}