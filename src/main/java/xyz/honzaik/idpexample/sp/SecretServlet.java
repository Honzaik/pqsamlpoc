package xyz.honzaik.idpexample.sp;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.GlobalConstants;
import xyz.honzaik.idpexample.WebUtil;

import java.io.IOException;
import java.io.PrintWriter;

/**
 * A webpage representing a resource that is only accessible by authorized users.
 * The authorization check is made by the SPFilter class.
 */
@WebServlet(name = "spSecretServlet", value = SPConstants.baseURL + "/secret")
public class SecretServlet extends HttpServlet
{

    private static final Logger LOG = LoggerFactory.getLogger(SecretServlet.class);
    private VelocityEngine velocityEngine = null;

    public void init() {
        this.velocityEngine = new VelocityEngine();
        this.velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "file,classpath");
        this.velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        this.velocityEngine.setProperty("resource.loader.file.path", getClass().getResource(GlobalConstants.VELOCITY_TEMPLATES_FOLDER).getPath());
        this.velocityEngine.init();
    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {


        LOG.info("secret servlet");
        resp.setContentType("text/html");
        resp.setCharacterEncoding("UTF-8");

        try
        {
            PrintWriter writer = resp.getWriter();
            VelocityContext vc = new VelocityContext();
            Template t = velocityEngine.getTemplate("secret.vm");

            t.merge(vc, writer);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }

    }

}
