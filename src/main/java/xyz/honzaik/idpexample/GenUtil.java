package xyz.honzaik.idpexample;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.primitive.NonnullSupplier;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.Properties;

/**
 * A helper class containing various static functions used in the web page rendering.
 */
public class GenUtil
{

    private static final Logger LOG = LoggerFactory.getLogger(GenUtil.class);

    public static Properties config = null;

    public static String getConfigFilePath() {
        return GenUtil.class.getResource("/config/").getPath() + GlobalConstants.configFileName;
    }
    public static Properties getConfig()
    {
        config = new Properties();
        try
        {
            LOG.info("getting config from " + getConfigFilePath());
            config.loadFromXML(new FileInputStream(getConfigFilePath()));
        }
        catch (IOException e)
        {
            LOG.error("FAILED TO LOAD CONFIG");
            throw new RuntimeException(e);
        }

        return config;
    }


}
