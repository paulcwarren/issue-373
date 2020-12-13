package gettingstarted;

import static com.github.paulcwarren.ginkgo4j.Ginkgo4jDSL.BeforeEach;
import static com.github.paulcwarren.ginkgo4j.Ginkgo4jDSL.Context;
import static com.github.paulcwarren.ginkgo4j.Ginkgo4jDSL.Describe;
import static com.github.paulcwarren.ginkgo4j.Ginkgo4jDSL.FIt;
import static com.jayway.restassured.RestAssured.given;

import java.io.ByteArrayInputStream;
import java.security.Principal;
import java.util.Collection;

import org.apache.http.HttpStatus;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.github.paulcwarren.ginkgo4j.Ginkgo4jSpringRunner;
import com.jayway.restassured.RestAssured;

@RunWith(Ginkgo4jSpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class Issue373Test {

    @Autowired
    private FileRepository fileRepo;
    @Autowired
    private FileContentStore fileContentStore;

    @Value("${local.server.port}")
    private int port;

    private File file;

    {
        Describe("Issue #373", () -> {
            BeforeEach(() -> {
                RestAssured.port = port;
            });

            Context("given an event handler that saves the entity", () -> {

                BeforeEach(() -> {

                    SecurityContextHolder.setContext(new SecurityContext() {

                        @Override
                        public Authentication getAuthentication() {
                            return new Authentication() {

                                @Override
                                public String getName() {
                                    return "test";
                                }

                                @Override
                                public Collection<? extends GrantedAuthority> getAuthorities() {
                                    return null;
                                }

                                @Override
                                public Object getCredentials() {
                                    return null;
                                }

                                @Override
                                public Object getDetails() {
                                    return null;
                                }

                                @Override
                                public Object getPrincipal() {
                                    return new Principal() {

                                        @Override
                                        public String getName() {
                                            return "test";
                                        }

                                    };
                                }

                                @Override
                                public boolean isAuthenticated() {
                                    return true;
                                }

                                @Override
                                public void setAuthenticated(boolean isAuthenticated)
                                        throws IllegalArgumentException {
                                }
                            };
                        }

                        @Override
                        public void setAuthentication(Authentication authentication) {
                        }
                    });

                    file = new File();
                    file.setMimeType("text/plain");
                    file.setSummary("test file summary");
                    file = fileRepo.save(file);
                    int i = 0;
                });

                FIt("should be able to set content", () -> {

                    given().
                        multiPart("file", "file", new ByteArrayInputStream("This is plain text content!".getBytes()), "text/plain").
                    when().
                        put("/files/" + file.getId()).
                    then().
                        statusCode(HttpStatus.SC_CREATED);
                });
            });
        });
    }

    @Test
    public void noop() {
    }
}
