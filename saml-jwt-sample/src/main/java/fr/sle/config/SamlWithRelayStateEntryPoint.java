package fr.sle.config;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

public class SamlWithRelayStateEntryPoint extends SAMLEntryPoint {


    @Override
    protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context, AuthenticationException exception) {

        WebSSOProfileOptions ssoProfileOptions;
        if (defaultOptions != null) {
            ssoProfileOptions = defaultOptions.clone();
        } else {
            ssoProfileOptions = new WebSSOProfileOptions();
        }

        // Not :
        // Add your custom logic here if you need it.
        // Original HttpRequest can be extracted from the context param
        // So you can let the caller pass you some special param which can be used to build an on-the-fly custom
        // relay state param


        ssoProfileOptions.setRelayState("http://localhost:4200");

        return ssoProfileOptions;
    }

}
