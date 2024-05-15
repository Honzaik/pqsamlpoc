package xyz.honzaik.idpexample;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Properties;

@WebServlet(name = "rootIndexServlet", value = "")
public class IndexServlet extends HttpServlet
{
    private static final Logger LOG = LoggerFactory.getLogger(IndexServlet.class);
    private VelocityEngine velocityEngine = null;


    public void init()
    {
        this.velocityEngine = new VelocityEngine();
        this.velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "file,classpath");
        this.velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        this.velocityEngine.setProperty("resource.loader.file.path", getClass().getResource(GlobalConstants.VELOCITY_TEMPLATES_FOLDER).getPath());
        this.velocityEngine.init();
    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        LOG.info("index servlet");
        resp.setContentType("text/html");
        try
        {
            Properties currentConfig = GenUtil.getConfig();

            PrintWriter writer = resp.getWriter();
            VelocityContext vc = new VelocityContext();
            vc.put("idpReset", currentConfig.get("idp:hostURL") + "/reset");
            vc.put("spReset", currentConfig.get("sp:hostURL") + "/reset");
            Template t = velocityEngine.getTemplate("index.vm");

            t.merge(vc, writer);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

}
