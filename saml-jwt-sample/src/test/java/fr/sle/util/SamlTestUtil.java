package fr.sle.util;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.InputStream;

/**
 * @author slemoine
 */
public class SamlTestUtil {

    public static Assertion loadAssertion(final String classpathResource) {

        try {
            // Init OPEN SAML
            DefaultBootstrap.bootstrap();

            // Parser pool xml
            BasicParserPool ppMgr = new BasicParserPool();
            ppMgr.setNamespaceAware(true);

            // Load saml assertion
            InputStream in = SamlTestUtil.class.getResourceAsStream(classpathResource);
            Document authAssertDoc = ppMgr.parse(in);
            Element authAssertRoot = authAssertDoc.getDocumentElement();

            // Unmarshalling
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(authAssertRoot);
            Assertion authSaml = (Assertion) unmarshaller.unmarshall(authAssertRoot);

            return authSaml;

        } catch (ConfigurationException | UnmarshallingException | XMLParserException e) {
            e.printStackTrace();
            throw new IllegalStateException("Error while loading saml assertion", e);
        }
    }

}
