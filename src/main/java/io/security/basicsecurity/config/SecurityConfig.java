package io.security.basicsecurity.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer.SessionFixationConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth ->
                        auth.requestMatchers("/login").permitAll()
                                .requestMatchers("/user").hasRole("USER")
                                .requestMatchers("/admin/pay").hasRole("ADMIN")
                                .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                                .anyRequest().authenticated()
                )
                .formLogin(handler ->
                        handler.successHandler((request, response, authentication) -> {
                                    RequestCache requestCache = new HttpSessionRequestCache();
                                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                                    String redirectUrl = savedRequest.getRedirectUrl();
                                    response.sendRedirect(redirectUrl);
                                }
                        )
                )
                .exceptionHandling(handler ->
                        handler
//                                .authenticationEntryPoint((request, response, authException) ->
//                                        response.sendRedirect("/login")
//                                )
                                .accessDeniedHandler((request, response, accessDeniedException) ->
                                        response.sendRedirect("/denied")
                                )
                )
                .logout(logout ->
                        logout.logoutUrl("/logout")
                                .logoutSuccessUrl("/login")
                                .addLogoutHandler((request, response, authentication) ->
                                        request.getSession().invalidate()
                                )
                                .logoutSuccessHandler((request, response, authentication) ->
                                        response.sendRedirect("/login")
                                )
                )
                .rememberMe(remember ->
                        remember.rememberMeParameter("remember")
                                .tokenValiditySeconds(3600)
                                .userDetailsService(userDetailsService))
                .sessionManagement(session ->
                        session.sessionFixation(SessionFixationConfigurer::changeSessionId)
                                .maximumSessions(1)
                                .maxSessionsPreventsLogin(true)
                )
                .build();
    }
}
