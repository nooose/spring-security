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

import static org.springframework.security.config.Customizer.withDefaults;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(auth ->
                        auth.requestMatchers("/user").hasRole("USER")
                                .requestMatchers("/admin/pay").hasRole("ADMIN")
                                .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                                .anyRequest().authenticated()
                )
                .formLogin(withDefaults())
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
