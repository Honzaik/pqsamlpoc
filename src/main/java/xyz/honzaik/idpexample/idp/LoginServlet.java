package xyz.honzaik.idpexample.idp;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.GenUtil;
import xyz.honzaik.idpexample.GlobalConstants;
import xyz.honzaik.idpexample.WebUtil;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * This servlet imitates a login portal at the IdP. There is a hardcoded user with email "user@example.com" with pw "password" that authenticates successfully.
 */
@WebServlet(name = "idpLoginServlet", value = IDPConstants.loginEndpointURL)
public class LoginServlet extends HttpServlet
{

    private static final Logger LOG = LoggerFactory.getLogger(LoginServlet.class);
    private VelocityEngine velocityEngine = null;

    public void init()
    {
        this.velocityEngine = new VelocityEngine();
        this.velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "file,classpath");
        this.velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        this.velocityEngine.setProperty("resource.loader.file.path", getClass().getResource(GlobalConstants.VELOCITY_TEMPLATES_FOLDER).getPath());
        this.velocityEngine.init();
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp)
    {
        String param = req.getParameter("loginSubmit");
        if (param == null)
        {
            throw new RuntimeException("wrong post format");
        }

        String email = req.getParameter("email");
        String password = req.getParameter("password");

        HttpSession session = req.getSession();
        session.setAttribute(IDPConstants.sessionAuthFinished, true);
        session.setAttribute(IDPConstants.sessionAuthResult, validateCredentials(email, password));
        session.setAttribute(IDPConstants.sessionAuthSubject, email);

        String backURL = session.getAttribute(IDPConstants.sessionLastURLAttrName).toString();

        if (backURL == null)
        {
            throw new RuntimeException("no back url");
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

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        LOG.info("starting login process");

        HttpSession session = req.getSession();

        if (WebUtil.isAuthenticated(session, IDPConstants.sessionAuthFinished))
        {
            throw new RuntimeException("Already logged in.");
        }

        AuthnRequest receivedRequest = (AuthnRequest) session.getAttribute(IDPConstants.sessionAuthnRequestAttrName);

        resp.setContentType("text/html");
        resp.setCharacterEncoding("UTF-8");
        try
        {
            PrintWriter writer = resp.getWriter();
            VelocityContext vc = new VelocityContext();
            Template t = velocityEngine.getTemplate("idpLogin.vm");

            vc.put("authnRequest", WebUtil.getHighlightedXML(receivedRequest));
            t.merge(vc, writer);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }


    }

    private boolean validateCredentials(String email, String password) {
        if (email.equals("user@example.com") && password.equals("password")) {
            return true;
        } else {
            return false;
        }
    }


}
