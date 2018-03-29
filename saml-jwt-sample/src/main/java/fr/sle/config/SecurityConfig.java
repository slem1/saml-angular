package fr.sle.config;

import fr.sle.config.jwt.JwtAuthenticationFilter;
import fr.sle.config.jwt.JwtAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.Http401AuthenticationEntryPoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author slemoine
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Rest security configuration for /api/
     */
    @Configuration
    @Order(1)
    public static class RestApiSecurityConfig extends WebSecurityConfigurerAdapter {

        private static final String apiMatcher = "/api/**";

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.addFilterBefore(new JwtAuthenticationFilter(apiMatcher, super.authenticationManager()), UsernamePasswordAuthenticationFilter.class);

            http.antMatcher(apiMatcher).authorizeRequests()
                    .anyRequest()
                    .authenticated();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(new JwtAuthenticationProvider());
        }
    }

    /**
     * Rest security configuration for /api/
     */
    @Configuration
    @Order(2)
    public static class AuthSecurityConfig extends WebSecurityConfigurerAdapter {

        private static final String apiMatcher = "/auth/token";

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http
                    .exceptionHandling()
                    .authenticationEntryPoint(new Http401AuthenticationEntryPoint("SAML2.0 - WEBSSO"));

            http.antMatcher(apiMatcher).authorizeRequests()
                    .anyRequest().authenticated();
        }
    }

    /**
     * Saml security config
     */
    @Configuration
    @Import(SamlSecurityConfig.class)
    public static class SamlConfig {

    }

}
