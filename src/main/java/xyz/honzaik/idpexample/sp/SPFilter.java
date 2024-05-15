package xyz.honzaik.idpexample.sp;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.WebUtil;

import java.io.IOException;

/**
 * Filter class that checks if a user is authorized to visit a certain webpage.
 * The authorization is represented by the session parameter SPConstants.sessionAuthAttrName.
 */
@WebFilter(servletNames = {"spSecretServlet"})
public class SPFilter extends HttpFilter
{

    private static final Logger LOG = LoggerFactory.getLogger(SPFilter.class);


    public void doFilter(HttpServletRequest req, HttpServletResponse resp, FilterChain c)
    {

        HttpSession ses = req.getSession();
        LOG.info("{}, {}", ses.getMaxInactiveInterval(), ses.getServletContext().getSessionTimeout());

        //Check if the current session is has authorization. If not, save the requested URL and redirect to the authentication page.
        if (!WebUtil.isAuthenticated(ses, SPConstants.sessionAuthAttrName))
        {
            String spAuthURL = req.getContextPath() + SPConstants.authEndpointURL;

            ses.setAttribute(SPConstants.sessionLastURLAttrName, req.getRequestURI());

            LOG.info("not authenticated, redirecting {}", spAuthURL);

            try
            {
                resp.sendRedirect(spAuthURL);
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }

        //The user is authorized.
        try
        {
            c.doFilter(req, resp);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (ServletException e)
        {
            throw new RuntimeException(e);
        }
    }

}
