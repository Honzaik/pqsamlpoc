package xyz.honzaik.idpexample.sp;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@WebServlet(name = "spIndexServlet", value = SPConstants.baseURL + "/")
public class IndexServlet extends HttpServlet
{

    private static final Logger LOG = LoggerFactory.getLogger(IndexServlet.class);

    public void init()
    {

    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        LOG.info("index servlet spp");
    }

}
