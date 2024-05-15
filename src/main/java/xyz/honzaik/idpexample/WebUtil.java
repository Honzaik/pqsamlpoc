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
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;


/**
 * A helper class containing various static functions used in the web page rendering.
 */
public class WebUtil
{

    private static final Logger LOG = LoggerFactory.getLogger(WebUtil.class);

    private static final String htmlHeader1 = """
                    <!doctype html>
                    <html>
                        <head>
                            <meta charset="utf-8">
                            <meta name="description" content="">
                            <meta name="viewport" content="width=device-width, initial-scale=1">
                            <title>
            """;
    private static final String htmlHeader2 = """
                            </title>
                            </head>
                        <body>
            """;

    private static final String htmlFooter = """
                        </body>
                    </html>
            """;

    /**
     * Helper function which outputs content into a <body> element and sets a title.
     *
     * @param w       output writer
     * @param content content that is written using the writer
     * @param title   title of the webpage. (<title>{title}</title>)
     */
    public static void writeHTMLContent(PrintWriter w, String content, String title)
    {
        w.print(WebUtil.htmlHeader1.trim());
        if (title != null)
        {
            w.print(title);
        }
        w.print(WebUtil.htmlHeader2.trim());
        w.print(content);
        w.print(WebUtil.htmlFooter.trim());
    }

    /**
     * Checks if the session user is authenticated.
     *
     * @param session  current session
     * @param attrName the name of the attribute which contains the information if user is authenticated
     * @return
     */
    public static boolean isAuthenticated(HttpSession session, String attrName)
    {
        Object authValue = session.getAttribute(attrName);
        if (authValue == null || !((boolean) authValue))
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    /**
     * Creates a SAML object from a HTTP POST request. Assumes the SAML object contains a signature.
     *
     * @param req the HTTP request
     * @return SAML object constructed from the HTTP request
     */
    public static SignableSAMLObject extractSAMLMessage(HttpServletRequest req)
    {
        HTTPPostDecoder decoder = new HTTPPostDecoder();

        NonnullSupplier<HttpServletRequest> supplier = () -> req;
        decoder.setHttpServletRequestSupplier(supplier);

        SignableSAMLObject samlObject = null;
        try
        {
            decoder.initialize();
            decoder.decode();
            MessageContext context = decoder.getMessageContext();
            samlObject = (SignableSAMLObject) context.getMessage();
        }
        catch (MessageDecodingException | ComponentInitializationException e)
        {
            throw new RuntimeException(e);
        }
        return samlObject;
    }

    /**
     * Wrapper for the redirectWithSAMLInPost defined below. This method takes a SAML input which is a Response
     *
     * @param velocityEngine
     * @param resp
     * @param object
     */
    public static void redirectWithSAMLInPost(VelocityEngine velocityEngine, HttpServletResponse resp, StatusResponseType object)
    {
        WebUtil.redirectWithSAMLInPost(velocityEngine, resp, object, object.getDestination());
    }

    /**
     * Wrapper for the redirectWithSAMLInPost defined below. This method takes a SAML input which is a Request
     *
     * @param velocityEngine
     * @param resp
     * @param object
     */
    public static void redirectWithSAMLInPost(VelocityEngine velocityEngine, HttpServletResponse resp, RequestAbstractType object)
    {
        WebUtil.redirectWithSAMLInPost(velocityEngine, resp, object, object.getDestination());
    }

    /**
     * This method creates a HTTP response containing a form which automatically submits and sends a POST request to the destination on behalf of the client.
     * The POST request contains the SAML message.
     *
     * @param velocityEngine Underlying templating engine
     * @param resp           HTTP response object
     * @param object         SAML message which is included in the POST request
     * @param destination    URL where the POST request is going to be sent
     */
    public static void redirectWithSAMLInPost(VelocityEngine velocityEngine, HttpServletResponse resp, SignableSAMLObject object, String destination)
    {
        MessageContext context = new MessageContext();
        context.setMessage(object);
        //SAMLBindingContext bindingContext = context.getSubcontext(SAMLBindingContext.class, true);
        //bindingContext.setRelayState("idk");

        SingleSignOnService endpoint = SAMLUtil.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        endpoint.setLocation(destination);

        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(endpoint);

        NonnullSupplier<HttpServletResponse> supplier = () -> resp;

        HTTPPostEncoder encoder = new HTTPPostEncoder();
        encoder.setMessageContext(context);
        encoder.setVelocityEngine(velocityEngine);
        encoder.setHttpServletResponseSupplier(supplier);

        try
        {
            encoder.initialize();
        }
        catch (ComponentInitializationException e)
        {
            throw new RuntimeException(e);
        }

        LOG.info("redirecting post autosubmit");

        try
        {
            encoder.encode();
        }
        catch (MessageEncodingException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a <pre> element containing a pretty printed XML
     * @param xmlObject XML input
     * @return String containing HTML
     */
    public static String getHighlightedXML(XMLObject xmlObject)
    {
        String serializedObject = null;
        try
        {
            Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject);
            out.marshall(xmlObject);
            Element el = xmlObject.getDOM();
            serializedObject = SerializeSupport.prettyPrintXML(el);
        }
        catch (MarshallingException e)
        {
            LOG.error(e.getMessage(), e);
        }

        serializedObject = serializedObject.replaceAll("<([^>/]*)/>", "&lt;~blue~$1~/~/&gt;");
        serializedObject = serializedObject.replaceAll("<([^>]*)>", "&lt;~blue~$1~/~&gt;");
        serializedObject = serializedObject.replaceAll("([\\w]+)=\"([^\"]*)\"", "~red~$1~/~~black~=\"~/~~green~$2~/~~black~\"~/~");
        serializedObject = serializedObject.replaceAll("~([a-z]+)~", "<span style=\"color: $1;\">");
        serializedObject = serializedObject.replace("~/~", "</span>");
        return "<pre style=\"white-space:break-spaces;\">" + serializedObject + "</pre>";
    }


}
