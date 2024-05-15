package xyz.honzaik.idpexample.idp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.GenUtil;
import xyz.honzaik.idpexample.SAMLUtil;
import xyz.honzaik.idpexample.WebUtil;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Security;
import java.util.Properties;

/**
 * Servlet for pre-processing requests from SP. Checks the signature(s) of the SAML request and if it is valid, it redirects the user to the resolve servlet.
 */
@WebServlet(name = "idpAuthServlet", value = IDPConstants.authEndpointURL)
public class AuthServlet extends HttpServlet
{

    private static final Logger LOG = LoggerFactory.getLogger(AuthServlet.class);

    private static Properties config = null;

    public void init()
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        SAMLUtil.initOpenSAML();
    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        LOG.info("index servlet idp");
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp)
    {
        config = GenUtil.getConfig();
        AuthnRequest authnRequest = (AuthnRequest) WebUtil.extractSAMLMessage(req);

        try
        {
            SAMLUtil.verifySAMLSignature(authnRequest);
            if (Boolean.parseBoolean(config.getProperty("idp:verifyHybridSig")))
            {
                SAMLUtil.verifyExtraSAMLSignature(authnRequest);
            }
            HttpSession session = req.getSession();
            session.setAttribute(IDPConstants.sessionAuthnRequestAttrName, authnRequest);
            resp.sendRedirect(req.getContextPath() + IDPConstants.resolveEndpointURL);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (SignatureException e)
        {
            throw new RuntimeException(e);
        }

    }


}
