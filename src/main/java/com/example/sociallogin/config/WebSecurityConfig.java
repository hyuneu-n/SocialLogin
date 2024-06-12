package com.example.sociallogin.config;

import com.example.sociallogin.filter.JwtAuthenticationFilter;
import com.example.sociallogin.handler.OAuth2LoginSuccessHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final DefaultOAuth2UserService defaultOAuth2UserService;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    protected SecurityFilterChain securityFilterChain(
            HttpSecurity httpSecurity,
            JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception{
        httpSecurity
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(CsrfConfigurer::disable)
                //Bearer방식으로 사용하는
                .httpBasic(HttpBasicConfigurer::disable)
                .sessionManagement(
                        sessionManagement ->
                                sessionManagement.sessionCreationPolicy(
                                        SessionCreationPolicy.STATELESS
                                ))
                .authorizeHttpRequests(
                        request ->
                                request.requestMatchers(
                                                "/",
                                                "/api/v1/oauth2/*")
                                        .permitAll()
                                        .requestMatchers("/api/v1/user/*")
                                        .hasRole("USER")
                                        .requestMatchers("/api/v1/admin/*")
                                        .hasRole("ADMIN")
                                        .anyRequest()
                                        .authenticated()
                )
                .oauth2Login(
                        oauth2 ->
                                oauth2.authorizationEndpoint(
                                                //http://localhost:8080/oauth2/authorization/naver
                                                //http://localhost:8080/api/v1/oauth2/authorization/naver
                                                endpoint ->
                                                        endpoint.baseUri(
                                                                "/api/v1/oauth2/authorization"
                                                        ))
                                        .redirectionEndpoint(
                                                endpoint ->
                                                        endpoint.baseUri(
                                                                "/login/oauth2/code/*"
                                                        ))
                                        .userInfoEndpoint(
                                                endpoint ->
                                                        endpoint.userService(
                                                                defaultOAuth2UserService
                                                        ))
                                        .successHandler(oAuth2LoginSuccessHandler)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}