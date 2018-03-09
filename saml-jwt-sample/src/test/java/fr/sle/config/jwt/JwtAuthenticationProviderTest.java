package fr.sle.config.jwt;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import fr.sle.config.SecurityConstant;
import org.joda.time.DateTime;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * @author slemoine
 */
@RunWith(SpringRunner.class)
public class JwtAuthenticationProviderTest {

    @Test
    public void supportsShouldReturnFalse() {
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();
        Assert.assertFalse(jwtAuthenticationProvider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    public void supportsShouldReturnTrue() {
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();
        Assert.assertFalse(jwtAuthenticationProvider.supports(JwtAuthenticationFilter.class));
    }

    @Test
    public void shouldAuthenticate() {
        final JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();
        final JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(getJWT(120));
        Authentication authentication = jwtAuthenticationProvider.authenticate(new JwtAuthenticationToken(jwtAuthenticationToken));
        Assert.assertTrue(authentication.isAuthenticated());
    }

    @Test(expected = CredentialsExpiredException.class)
    public void shouldFailOnExpiredToken() {
        final JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();
        final JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(getJWT(-120));
        jwtAuthenticationProvider.authenticate(new JwtAuthenticationToken(jwtAuthenticationToken));
    }

    @Test(expected = BadCredentialsException.class)
    public void shouldFailOnBadSignature() {
        final JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();

        String jwt = getJWT(120);
        int signIndex = jwt.lastIndexOf('.');
        jwt = jwt.substring(0, signIndex) + ".123456";

        final JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt);
        jwtAuthenticationProvider.authenticate(new JwtAuthenticationToken(jwtAuthenticationToken));
    }

    private String getJWT(int duration) {

        final DateTime dateTime = DateTime.now();

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.expirationTime(dateTime.plusMinutes(duration).toDate());
        jwtClaimsSetBuilder.claim("APP", "SAMPLE");

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSetBuilder.build());
        try {
            signedJWT.sign(new MACSigner(SecurityConstant.JWT_SECRET));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }

        return signedJWT.serialize();
    }

}
