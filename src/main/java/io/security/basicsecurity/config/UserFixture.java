package io.security.basicsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class UserFixture {

    @Bean
    public UserDetailsManager users() {
        UserDetails user = createUser("user", "1111", "USER");
        UserDetails sys = createUser("sys", "2222", "USER", "SYS");
        UserDetails admin = createUser("admin", "3333", "ADMIN", "SYS", "USER");

        return new InMemoryUserDetailsManager(user, sys, admin);
    }

    private UserDetails createUser(String username, String password, String... roles) {
        return User.builder()
                .username(username)
                .password("{noop}" + password)
                .roles(roles)
                .build();
    }
}
