package ziponia.spring.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@Configuration
@EnableOAuth2Client
@EnableWebSecurity
public class RootSecurityConfig {

    @Configuration
    public static class FormSecurityConfigAdapter extends WebSecurityConfig {}

    @Order(2)
    @Configuration
    public static class AuthorizationSecurityConfigAdapter extends AuthorizationServerSecurityConfig {}

    @Configuration
    @EnableResourceServer
    public static class ApiSecurityConfigAdapter extends ResourceServerConfig {}

}
