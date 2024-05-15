package xyz.honzaik.idpexample;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Servlet which just invalidates the current session for demo purposes.
 */
@WebServlet(name = "resetServlet", value = "/reset")
public class ResetServlet extends HttpServlet
{
    private static final Logger LOG = LoggerFactory.getLogger(ResetServlet.class);

    public void init()
    {

    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        LOG.info("reset servlet");
        resp.setContentType("text/html");
        if (req.getHeader("Origin") != null) {
            resp.setHeader("Access-Control-Allow-Origin", req.getHeader("Origin"));
            resp.setHeader("Access-Control-Allow-Credentials", "true");
        }

        try
        {
            req.getSession().invalidate();

            PrintWriter writer = resp.getWriter();
            WebUtil.writeHTMLContent(writer, "Successfully reset cookies.", "Reset demo");
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

}
