package xyz.honzaik.idpexample.sp;


import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.*;
import xyz.honzaik.idpexample.idp.IDPConstants;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Properties;
import java.util.UUID;

/**
 * Handles user authentication by communicating with the IdP.
 * Creates AuthnRequest for the IdP and processes the response.
 * If the user is authenticated, it sets the authorization flag for the current session and redirects the user to his requested URL.
 */
@WebServlet(name = "spAuthServlet", value = SPConstants.authEndpointURL)
public class AuthServlet extends HttpServlet
{

    private static final Logger LOG = LoggerFactory.getLogger(AuthServlet.class);

    private String contextURL = null;
    private KeyStore keyStore = null;

    private VelocityEngine velocityEngine = null;

    private Properties config = null;

    public void init()
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        SAMLUtil.initOpenSAML();

        this.velocityEngine = new VelocityEngine();
        this.velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "file,classpath");
        this.velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        this.velocityEngine.setProperty("resource.loader.file.path", getClass().getResource(GlobalConstants.VELOCITY_TEMPLATES_FOLDER).getPath());
        this.velocityEngine.init();
    }

    private void reloadKeyStore() {
        String keyStorePath = getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + config.getProperty("sp:keyStoreFilename");
        this.keyStore = KeyUtils.loadKeyStore(keyStorePath, config.getProperty("sp:keyStorePassword"));
    }

    /**
     * Handles POST requests sent to this servlet (/sp/auth).
     * We expect POST body to contain a SAML message that is an instance of Response.
     *
     * @param req  an {@link HttpServletRequest} object that
     *             contains the request the client has made
     *             to the servlet
     * @param resp an {@link HttpServletResponse} object that
     *             contains the response the servlet sends
     *             to the client
     */
    public void doPost(HttpServletRequest req, HttpServletResponse resp)
    {
        config = GenUtil.getConfig();
        reloadKeyStore();

        //Decode SAML message from the POST body.
        Response response = (Response) WebUtil.extractSAMLMessage(req);

        //verify traditional signature and also verify extra (pqc) signature. The function expects the SAML message to be signed using a hybrid signature. The verification fails if one of the signatures is invalid.
        try
        {
            SAMLUtil.verifySAMLSignature(response);
            if (Boolean.parseBoolean(config.getProperty("sp:verifyHybridSig")))
            {
                SAMLUtil.verifyExtraSAMLSignature(response);
            }
        }
        catch (SignatureException e)
        {
            throw new RuntimeException(e);
        }

        String responseXMLString = WebUtil.getHighlightedXML(response);

        //We expect the Response to contain one EncryptedAssertion.
        EncryptedAssertion encryptedAssertion = response.getEncryptedAssertions().get(0);
        //Decrypt the EncryptedAssertion into Assertion
        Assertion decryptedAssertion = SAMLUtil.decryptAssertion(encryptedAssertion, this.keyStore);

        SAMLUtil.logSAMLObject(decryptedAssertion);

        LOG.info(response.getStatus().getStatusCode().getValue());

        //If the Response contains a status code that signifies success, then notify the user that he has successfully authenticated. The message contains a button which after pressing redirects him (by redirecting him to this servlet via GET) to the previously requested URL.
        if (response.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS))
        {
            LOG.info("authenticated");
            HttpSession session = req.getSession();
            session.setAttribute(SPConstants.sessionAuthAttrName, true); //Sets authorization flag to true.
            resp.setContentType("text/html");
            resp.setCharacterEncoding("UTF-8");
            try
            {
                PrintWriter writer = resp.getWriter();
                VelocityContext vc = new VelocityContext();
                vc.put("response", responseXMLString);
                vc.put("decryptedAssertion", WebUtil.getHighlightedXML(decryptedAssertion));
                vc.put("email", decryptedAssertion.getSubject().getNameID().getValue());
                Template t = velocityEngine.getTemplate("spSuccess.vm");
                t.merge(vc, writer);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
        else
        { //Authentication failed according to the IdP. Notify user.
            resp.setContentType("text/html");
            resp.setCharacterEncoding("UTF-8");
            try
            {
                PrintWriter writer = resp.getWriter();
                VelocityContext vc = new VelocityContext();
                vc.put("response", responseXMLString);
                vc.put("decryptedAssertion", WebUtil.getHighlightedXML(decryptedAssertion));
                Template t = velocityEngine.getTemplate("spFailed.vm");
                t.merge(vc, writer);

            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Handles GET requests sent to this servlet (/sp/auth).
     *
     * @param req  an {@link HttpServletRequest} object that
     *             contains the request the client has made
     *             of the servlet
     * @param resp an {@link HttpServletResponse} object that
     *             contains the response the servlet sends
     *             to the client
     */
    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        config = GenUtil.getConfig();
        reloadKeyStore();
        HttpSession session = req.getSession();

        //Check if the user is authenticated. In this case the user is to be redirected to his previously requested URL before he was redirected to authenticate.
        if (WebUtil.isAuthenticated(session, SPConstants.sessionAuthAttrName))
        {
            String backURL = req.getContextPath() + SPConstants.baseURL + "/";
            Object lastURL = session.getAttribute(SPConstants.sessionLastURLAttrName);
            //If case the session does not remember the last requested URL, redirect the user to the baseURL so he does not get stuck in a redirect loop.
            if (lastURL != null && lastURL instanceof String)
            {
                backURL = (String) lastURL;
            }
            try
            {
                resp.sendRedirect(backURL);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
        else if (req.getParameter("redirect") != null)
        { //The user is not authenticated but the GET parameter redirect is present. This signifies that the user is to be redirected to the IdP.
            setContextURL(req.getContextPath());
            authenticateAtIDP(resp);
        }
        else
        { //This page is shown to the user after he is redirected from the SPFilter. On this page he can click a button to begin authentication.
            resp.setContentType("text/html");
            resp.setCharacterEncoding("UTF-8");
            try
            {
                PrintWriter writer = resp.getWriter();
                VelocityContext vc = new VelocityContext();
                Template t = velocityEngine.getTemplate("spLogin.vm");

                t.merge(vc, writer);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
    }

    private String getContextURL()
    {
        return this.contextURL;
    }

    private void setContextURL(String url)
    {
        this.contextURL = url;
    }

    private Issuer buildIssuer(String issuerName)
    {
        Issuer issuer = SAMLUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(issuerName);
        return issuer;
    }

    private String getDestinationIDP()
    {
        return config.getProperty("idp:hostURL") + this.getContextURL() + IDPConstants.authEndpointURL;
    }

    private String getConsumerServiceURL()
    {
        return config.getProperty("sp:hostURL") + this.getContextURL() + SPConstants.authEndpointURL;
    }

    private Subject buildSubject(String subjectName)
    {
        NameID nameID = SAMLUtil.buildSAMLObject(NameID.class);
        nameID.setValue(subjectName);

        Subject subject = SAMLUtil.buildSAMLObject(Subject.class);
        subject.setNameID(nameID);
        return subject;
    }

    private AuthnRequest buildAuthnRequest()
    {
        AuthnRequest authnRequest = SAMLUtil.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssuer(buildIssuer(SPConstants.issuerName));
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setDestination(getDestinationIDP());
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(getConsumerServiceURL());
        authnRequest.setID("HO_" + UUID.randomUUID());
        //authnRequest.setSubject(buildSubject("test@example.com"));


        //insert KEM certs
        Extensions extensions = SAMLUtil.buildSAMLObject(Extensions.class);
        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);
        KeyInfo keyInfo = null;
        try
        {
            X509Certificate kemCert = (X509Certificate) this.keyStore.getCertificate(GlobalConstants.KEM_PRIV_KEY_KEYSTORE_NAME);
            X509Credential x509cred = new BasicX509Credential(kemCert);
            keyInfo = factory.newInstance().generate(x509cred);
        }
        catch (KeyStoreException | SecurityException e)
        {
            throw new RuntimeException(e);
        }

        KeyInfoSupport.addKeyName(keyInfo, "primaryEncryptionCert");

        extensions.getUnknownXMLObjects().add(keyInfo);

        if (Boolean.parseBoolean(config.getProperty("sp:useHybridEnc"))) {
            try
            {
                X509Certificate kemCert = (X509Certificate) this.keyStore.getCertificate(GlobalConstants.KEM_EXTRA_PRIV_KEY_KEYSTORE_NAME);
                X509Credential x509cred = new BasicX509Credential(kemCert);
                keyInfo = factory.newInstance().generate(x509cred);
                KeyInfoSupport.addKeyName(keyInfo, "secondaryEncryptionCert");

            }
            catch (KeyStoreException | SecurityException e)
            {
                throw new RuntimeException(e);
            }

            extensions.getUnknownXMLObjects().add(keyInfo);
        }

        authnRequest.setExtensions(extensions);

        return authnRequest;
    }

    private void authenticateAtIDP(HttpServletResponse resp)
    {
        AuthnRequest authnRequest = buildAuthnRequest();

        ArrayList<String> signatureAlgs = new ArrayList<>();
        signatureAlgs.add(config.getProperty("sp:signatureAlg"));
        signatureAlgs.add(config.getProperty("sp:signatureAlgExtra"));
        SAMLUtil.signSAMLMessage(authnRequest, Boolean.parseBoolean(config.getProperty("sp:useHybridSig")), this.keyStore, signatureAlgs, config.getProperty("sp:referenceDigestAlg"));

        SAMLUtil.logSAMLObject(authnRequest);

        WebUtil.redirectWithSAMLInPost(this.velocityEngine, resp, authnRequest);
    }


}
