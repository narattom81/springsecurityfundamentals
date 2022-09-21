package com.bharath.springcloud.security.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.bharath.springcloud.security.UserDetailsServiceImpl;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.mvcMatchers(HttpMethod.GET, "/couponapi/coupons/{code:^[A-Z]*$}", "/index", "/showGetCoupon",
						"/getCoupon", "/couponDetails")
				//.hasAnyRole("USER", "ADMIN")
				.permitAll()
				.mvcMatchers(HttpMethod.GET, "/showCreateCoupon", "/createCoupon", "/createResponse").hasRole("ADMIN")
				.mvcMatchers(HttpMethod.POST, "/getCoupon").hasAnyRole("USER", "ADMIN")
				.mvcMatchers(HttpMethod.POST, "/couponapi/coupons", "/saveCoupon", "/getCoupon").hasRole("ADMIN")
				.mvcMatchers("/", "/login", "/logout", "/showReg", "/registerUser").permitAll().anyRequest().denyAll()
				.and().logout().logoutSuccessUrl("/");//.and().csrf().disable();


		http.cors(c -> {
			CorsConfigurationSource cs=request->{
				CorsConfiguration cc=new CorsConfiguration();
				cc.setAllowedOrigins(List.of("http://localhost:3000"));
				cc.setAllowedMethods(List.of("GET"));
				return cc;
			};
			c.configurationSource(cs);

		});

		http.csrf(c->{
			c.ignoringAntMatchers("/couponapi/coupons/**");
			//RequestMatcher r=new RegexRequestMatcher("/couponapi/coupons/{code:^[A-Z]*$}","POST");
			RequestMatcher r=new MvcRequestMatcher(new HandlerMappingIntrospector(),"/getCoupon");
			c.ignoringRequestMatchers(r);
		});

	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

}
