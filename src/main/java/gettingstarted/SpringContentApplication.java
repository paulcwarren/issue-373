package gettingstarted;

import static java.lang.String.format;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.content.commons.annotations.HandleAfterSetContent;
import org.springframework.content.commons.annotations.StoreEventHandler;
import org.springframework.content.commons.repository.events.AfterSetContentEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableTransactionManagement
public class SpringContentApplication {

    private static final Log logger = LogFactory.getLog(SpringContentApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SpringContentApplication.class, args);
    }

    @Configuration
    @EnableJpaRepositories(basePackages = {"gettingstarted", "org.springframework.versions"})
    public static class StoreConfig {

        @Bean
        public MyEventHandler handler() {
            return new MyEventHandler();
        }
    }

    @StoreEventHandler
    public static class MyEventHandler {

        @Autowired
        private FileRepository repo;

        @HandleAfterSetContent
        @Order(Ordered.HIGHEST_PRECEDENCE)
        public void afterSetContent(AfterSetContentEvent event) {

            if (event.getSource() != null) {

                File f = (File) event.getSource();
                logger.info(format("MyEventHandler::afterSetContent modifying file %s", f.getId()));

                f.setName(f.getName() + " modified");
                f = repo.saveAndFlush(f);

                logger.info(format("MyEventHandler::afterSetContent creating working copy of file %s", f.getId()));
                f = repo.lock(f);
                File fwc = repo.workingCopy(f);
                fwc.setName(f.getName() + " pwc");
                fwc = repo.saveAndFlush(fwc);
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

        protected static String REALM = "SPRING_CONTENT";

        @Bean
        public AuthenticationEntryPoint getBasicAuthEntryPoint() {
            return new AuthenticationEntryPoint();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .and().httpBasic().realmName(REALM).authenticationEntryPoint(getBasicAuthEntryPoint())
                    .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**");
        }
    }

    public static class AuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

        @Override
        public void commence(final HttpServletRequest request, final HttpServletResponse response,
                             final AuthenticationException authException) throws IOException {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.addHeader("WWW-Authenticate", "Basic realm=" + getRealmName() + "");

            PrintWriter writer = response.getWriter();
            writer.println("HTTP Status 401 : " + authException.getMessage());
        }

        @Override
        public void afterPropertiesSet() {
            setRealmName(SpringContentApplication.SpringSecurityConfig.REALM);
            super.afterPropertiesSet();
        }
    }
}

