package fr.sle.controllers;

import com.nimbusds.jose.JOSEException;
import fr.sle.WithMockSaml;
import fr.sle.dto.ApiToken;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author slemoine
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class AuthControllerTest {

    @WithMockSaml(samlAssertFile = "/saml-auth-assert.xml")
    @Test
    public void testAuthController() throws JOSEException {

        final AuthController authController = new AuthController();

        final ApiToken apiToken = authController.token();

        Assert.assertNotNull(apiToken);
        Assert.assertTrue(apiToken.getToken().length() > 0);
    }
}
