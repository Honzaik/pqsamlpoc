package xyz.honzaik.idpexample.idp;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.jcajce.interfaces.CMCEKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.cmce.BCCMCEPublicKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.PublicKey;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.*;
import xyz.honzaik.idpexample.tools.EncryptedKeyKey;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

/**
 * This servlet checks if user is already logged in at the IdP (based on a cookie). If not, the user is redirected to the login servlet. If the user is logged in, the servlet crafts a SAML Response for the SP.
 */
@WebServlet(name = "idpResolveServlet", value = IDPConstants.resolveEndpointURL)
public class ResolveServlet extends HttpServlet
{

    private static final Logger LOG = LoggerFactory.getLogger(ResolveServlet.class);

    private VelocityEngine velocityEngine = null;
    private KeyStore keyStore = null;

    private Properties config = null;

    public void init()
    {

        Security.insertProviderAt(new BouncyCastlePQCProvider(), 1);
        Security.insertProviderAt(new BouncyCastleProvider(), 2);
        SAMLUtil.initOpenSAML();

        this.velocityEngine = new VelocityEngine();
        this.velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "classpath");
        this.velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        this.velocityEngine.init();
    }

    private void reloadKeyStore() {
        String keyStorePath = getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + config.getProperty("idp:keyStoreFilename");
        keyStore = KeyUtils.loadKeyStore(keyStorePath, config.getProperty("idp:keyStorePassword"));
    }

    // Check if user is already logged in. If not, redirect to login page. If yes, craft a SAML Response.
    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        config = GenUtil.getConfig();
        reloadKeyStore();
        LOG.info("resolve start");

        HttpSession session = req.getSession();

        //user is not logged it, redirect to login page.
        if (!WebUtil.isAuthenticated(session, IDPConstants.sessionAuthFinished))
        {
            session.setAttribute(IDPConstants.sessionLastURLAttrName, req.getRequestURL());
            try
            {
                resp.sendRedirect(req.getContextPath() + IDPConstants.loginEndpointURL);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
        else //user is logged in, create a SAML Response.
        {
            AuthnRequest authnRequest = (AuthnRequest) session.getAttribute(IDPConstants.sessionAuthnRequestAttrName);

            //AuthnRequest was already verified before
            Response SAMLResponse = buildResponse(authnRequest, (boolean) session.getAttribute(IDPConstants.sessionAuthResult), (String) session.getAttribute(IDPConstants.sessionAuthSubject));

            ArrayList<String> signatureAlgs = new ArrayList<>();
            signatureAlgs.add(config.getProperty("idp:signatureAlg"));
            signatureAlgs.add(config.getProperty("idp:signatureAlgExtra"));
            SAMLUtil.signSAMLMessage(SAMLResponse, Boolean.parseBoolean(config.getProperty("idp:useHybridSig")), this.keyStore, signatureAlgs, config.getProperty("idp:referenceDigestAlg"));

            SAMLUtil.logSAMLObject(SAMLResponse);

            WebUtil.redirectWithSAMLInPost(this.velocityEngine, resp, SAMLResponse);
        }

    }


    private Issuer buildIssuer(String issuerName)
    {
        Issuer issuer = SAMLUtil.buildSAMLObject(Issuer.class);
        issuer.setValue(issuerName);
        return issuer;
    }

    private Assertion buildAssertion(AuthnRequest authnRequest, String subjectEmail)
    {
        Assertion assertion = SAMLUtil.buildSAMLObject(Assertion.class);
        assertion.setIssuer(buildIssuer(IDPConstants.issuerName));

        Subject subject = SAMLUtil.buildSAMLObject(Subject.class);

        NameID nameID = SAMLUtil.buildSAMLObject(NameID.class);
        nameID.setValue(subjectEmail);

        subject.setNameID(nameID);

        SubjectConfirmation confirmation = SAMLUtil.buildSAMLObject(SubjectConfirmation.class);
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData data = SAMLUtil.buildSAMLObject(SubjectConfirmationData.class);
        data.setInResponseTo(authnRequest.getID());
        data.setNotBefore(Instant.now());
        data.setNotOnOrAfter(Instant.ofEpochMilli(System.currentTimeMillis() + 100000));
        data.setRecipient(authnRequest.getAssertionConsumerServiceURL());

        confirmation.setSubjectConfirmationData(data);

        subject.getSubjectConfirmations().add(confirmation);

        assertion.setSubject(subject);

        return assertion;

    }

    private Response buildResponse(AuthnRequest authnRequest, boolean authResult, String subjectEmail)
    {
        Response response = SAMLUtil.buildSAMLObject(Response.class);
        response.setIssuer(buildIssuer(IDPConstants.issuerName));
        response.setDestination(authnRequest.getAssertionConsumerServiceURL());
        response.setIssueInstant(Instant.now());
        response.setInResponseTo(authnRequest.getID());
        response.setID("HOP_" + UUID.randomUUID());

        Status status = SAMLUtil.buildSAMLObject(Status.class);
        StatusCode statusCode = SAMLUtil.buildSAMLObject(StatusCode.class);
        statusCode.setValue(authResult ? StatusCode.SUCCESS : StatusCode.AUTHN_FAILED);
        status.setStatusCode(statusCode);

        response.setStatus(status);

        Assertion assertion = buildAssertion(authnRequest, subjectEmail);

        ArrayList<X509Certificate> certsFromExtensions = SAMLUtil.extractCertificatesFromExtensions(authnRequest);
        ArrayList<String> encAlgIds = new ArrayList<>();
        encAlgIds.add(config.getProperty("sp:kemAlg"));
        encAlgIds.add(config.getProperty("sp:kemAlgExtra"));

        EncryptedAssertion encryptedAssertion = SAMLUtil.encryptAssertion(Boolean.parseBoolean(config.getProperty("idp:useHybridEnc")), assertion, certsFromExtensions, encAlgIds);

        response.getEncryptedAssertions().add(encryptedAssertion);

        return response;
    }

}
