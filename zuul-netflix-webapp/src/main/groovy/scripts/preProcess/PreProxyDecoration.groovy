package scripts.preProcess


import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.Mockito
import org.mockito.runners.MockitoJUnitRunner

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import com.netflix.zuul.groovy.ProxyFilter
import com.netflix.zuul.context.RequestContext
import com.netflix.zuul.exception.ProxyException

/**
 * Created by IntelliJ IDEA.
 * User: mcohen
 * Date: 1/5/12
 * Time: 1:03 PM
 * To change this template use File | Settings | File Templates.
 */
public class PreProxyDecoration extends ProxyFilter {

    @Override
    String filterType() {
        return "pre"
    }

    @Override
    int filterOrder() {
        return 20
    }

    @Override
    boolean shouldFilter() {
        return true
    }

    @Override
    Object run() {
        if (RequestContext.currentContext.getRequest().getParameter("url") != null) {
            try {
                RequestContext.getCurrentContext().proxyHost = new URL(RequestContext.currentContext.getRequest().getParameter("url"))
                RequestContext.currentContext.setProxyResponseGZipped(true)
            } catch (MalformedURLException e) {
                throw new ProxyException(e, "Malformed URL", 400, "MALFORMED_URL")
            }
        }
        setProxyHeaders()
        return null
    }

    void setProxyHeaders() {
        RequestContext context = RequestContext.currentContext
        context.addProxyRequestHeader("X-Netflix.request.toplevel.uuid", UUID.randomUUID().toString())
        context.addProxyRequestHeader("X-Forwarded-For", context.getRequest().remoteAddr)
        context.addProxyRequestHeader("X-Netflix.client-host", context.getRequest().getHeader("Host"))
        if (context.getRequest().getHeader("X-Forwarded-Proto") != null) {
            context.addProxyRequestHeader("X-Netflix.client-proto", context.getRequest().getHeader("X-Forwarded-Proto"))
        }
//        context.addProxyRequestHeader("X-Netflix-User-Id", getUserID) //todo double check this requirement


    }


    @RunWith(MockitoJUnitRunner.class)
    public static class TestUnit {

        @Mock
        HttpServletResponse response
        @Mock
        HttpServletRequest request





        @Test
        public void testPreProxyHeaders() {

            PreProxyDecoration ppd = new PreProxyDecoration()
            HttpServletRequest request = Mockito.mock(HttpServletRequest.class)
            RequestContext.currentContext.request = request
            Mockito.when(request.remoteAddr).thenReturn("1.1.1.1")
            Mockito.when(request.getHeader("Host")).thenReturn("moldfarm.com")
            Mockito.when(request.getHeader("X-Forwarded-Proto")).thenReturn("https")

            ppd.setProxyHeaders()

            Map<String, String> headers = RequestContext.currentContext.proxyRequestHeaders
            Assert.assertNotNull(headers["x-netflix.request.toplevel.uuid"])
            Assert.assertNotNull(headers["x-forwarded-for"])
            Assert.assertNotNull(headers["x-netflix.client-host"])
            Assert.assertNotNull(headers["x-netflix.client-proto"])

        }

    }

}
