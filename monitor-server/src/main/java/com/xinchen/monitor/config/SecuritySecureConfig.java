package com.xinchen.monitor.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * @author Xin Chen (xinchenmelody@gmail.com)
 * @version 1.0
 * @date Created In 2019/5/22 0:16
 */
@Configuration
public class SecuritySecureConfig extends WebSecurityConfigurerAdapter {

    /** context path */
    private final String adminContextPath;

    public SecuritySecureConfig(AdminServerProperties adminServerProperties) {
        this.adminContextPath = adminServerProperties.getContextPath();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // login success redirect to adminContextPath
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(adminContextPath+"/");


        http.authorizeRequests()
                //Grants public access to all static assets and the login page.
                .antMatchers(adminContextPath + "/assets/**").permitAll()
                .antMatchers(adminContextPath + "/login").permitAll()
                //	Every other request must be authenticated.
                .anyRequest().authenticated()
                .and()
                //Configures login and logout.
                .formLogin().loginPage(adminContextPath + "/login").successHandler(successHandler).and()
                .logout().logoutUrl(adminContextPath + "/logout").and()
                //Enables HTTP-Basic support. This is needed for the Spring Boot Admin Client to register.
                .httpBasic().and()
                .csrf()
                //	Enables CSRF-Protection using Cookies
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringAntMatchers(
                        //	Disables CSRF-Protection the endpoint the Spring Boot Admin Client uses to register.
                        adminContextPath + "/instances",
                        //Disables CSRF-Protection for the actuator endpoints.
                        adminContextPath + "/actuator/**"
                );

    }
}
