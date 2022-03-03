package com.example.security_example.security;

import com.example.security_example.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.security_example.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicatonUserService;
    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicatonUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicatonUserService = applicatonUserService;
    }

    // tips: ctrl+o opens methods extented :)
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // orders of these matchers matter. executed orderly.
        // csrf stands for "cross site request forgery"

        http
                .csrf().disable()
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .authorizeRequests()
                .antMatchers("/", "/index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .formLogin() // form-based authentication --> can logout
                    .loginPage("/login")
                    .permitAll()
                    .defaultSuccessUrl("/courses", true)
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe() // defaults to 2 weeks
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                    .rememberMeParameter("rememeber-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
//                .httpBasic(); // basic authentication  --> cannot logout
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails userNuman1 = User.builder()
//                .username("usernuman1")
//                .password(passwordEncoder.encode("password"))
////                .roles(STUDENT.name())
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails adminNuman = User.builder()
//                .username("adminnuman")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails adminNuman2 = User.builder()
//                .username("adminnuman2")
//                .password(passwordEncoder.encode("password123"))
////                .roles(ADMINTRAINEE.name())
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                userNuman1,
//                adminNuman,
//                adminNuman2
//        );
//    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicatonUserService);
        return provider;
    }

}
