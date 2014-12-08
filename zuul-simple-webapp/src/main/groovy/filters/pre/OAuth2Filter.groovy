/*
 * Copyright 2013 Netflix, Inc.
 *
 *      Licensed under the Apache License, Version 2.0 (the "License");
 *      you may not use this file except in compliance with the License.
 *      You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *      Unless required by applicable law or agreed to in writing, software
 *      distributed under the License is distributed on an "AS IS" BASIS,
 *      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *      See the License for the specific language governing permissions and
 *      limitations under the License.
 */



import com.netflix.config.DynamicIntProperty
import com.netflix.config.DynamicPropertyFactory
import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.constants.ZuulConstants
import com.netflix.zuul.context.Debug
import com.netflix.zuul.context.RequestContext
import com.netflix.zuul.util.HTTPRequestUtils
import org.apache.http.Header
import org.apache.http.HttpHost
import org.apache.http.HttpRequest
import org.apache.http.HttpResponse
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpPut
import org.apache.http.client.params.ClientPNames
import org.apache.http.conn.ClientConnectionManager
import org.apache.http.conn.scheme.PlainSocketFactory
import org.apache.http.conn.scheme.Scheme
import org.apache.http.conn.scheme.SchemeRegistry
import org.apache.http.entity.InputStreamEntity
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager
import org.apache.http.message.BasicHeader
import org.apache.http.message.BasicHttpRequest
import org.apache.http.params.CoreConnectionPNames
import org.apache.http.params.HttpParams
import org.apache.http.protocol.HttpContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import javax.servlet.http.HttpServletRequest
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.GZIPInputStream

class OAuth2Filter extends ZuulFilter {

    public static final String CONTENT_ENCODING = "Content-Encoding";

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2Filter.class);
    private static final Runnable CLIENTLOADER = new Runnable() {
        @Override
        void run() {
            loadClient();
        }
    }

    private static final DynamicIntProperty SOCKET_TIMEOUT =
        DynamicPropertyFactory.getInstance().getIntProperty(ZuulConstants.ZUUL_HOST_SOCKET_TIMEOUT_MILLIS, 5000)

    private static final DynamicIntProperty CONNECTION_TIMEOUT =
        DynamicPropertyFactory.getInstance().getIntProperty(ZuulConstants.ZUUL_HOST_CONNECT_TIMEOUT_MILLIS, 2000)

    private static final AtomicReference<HttpClient> CLIENT = new AtomicReference<HttpClient>(newClient());

    private static final Timer CONNECTION_MANAGER_TIMER = new Timer(true);

    // cleans expired connections at an interval
    static {
        SOCKET_TIMEOUT.addCallback(CLIENTLOADER)
        CONNECTION_TIMEOUT.addCallback(CLIENTLOADER)
        CONNECTION_MANAGER_TIMER.schedule(new TimerTask() {
            @Override
            void run() {
                try {
                    final HttpClient hc = CLIENT.get();
                    if (hc == null) return;
                    hc.getConnectionManager().closeExpiredConnections();
                } catch (Throwable t) {
                    LOG.error("error closing expired connections", t);
                }
            }
        }, 30000, 5000)
    }

    public OAuth2FilterRoutingFilter() {}

    private static final ClientConnectionManager newConnectionManager() {
        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(
                new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));

        ClientConnectionManager cm = new ThreadSafeClientConnManager(schemeRegistry);
        cm.setMaxTotal(Integer.parseInt(System.getProperty("zuul.max.host.connections", "200")));
        cm.setDefaultMaxPerRoute(Integer.parseInt(System.getProperty("zuul.max.host.connections", "20")));

        return cm;
    }

    @Override
    String filterType() {
        return 'pre'
    }

    @Override
    int filterOrder() {
        return 10
    }

    boolean shouldFilter() {
        return !RequestContext.currentContext.getRouteHost().equals(new URL("http://localhost:3000/"))
    }

    private static final void loadClient() {
        final HttpClient oldClient = CLIENT.get();
        CLIENT.set(newClient())
        if (oldClient != null) {
            CONNECTION_MANAGER_TIMER.schedule(new TimerTask() {
                @Override
                void run() {
                    try {
                        oldClient.getConnectionManager().shutdown();
                    } catch (Throwable t) {
                        LOG.error("error shutting down old connection manager", t);
                    }
                }
            }, 30000);
        }

    }

    private static final HttpClient newClient() {
        // I could statically cache the connection manager but we will probably want to make some of its properties
        // dynamic in the near future also
        HttpClient httpclient = new DefaultHttpClient(newConnectionManager());
        HttpParams httpParams = httpclient.getParams();
        httpParams.setIntParameter(CoreConnectionPNames.SO_TIMEOUT, SOCKET_TIMEOUT.get())
        httpParams.setIntParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, CONNECTION_TIMEOUT.get())
        httpclient.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler(0, false))
        httpParams.setParameter(ClientPNames.COOKIE_POLICY, org.apache.http.client.params.CookiePolicy.IGNORE_COOKIES);
        httpclient.setRedirectStrategy(new org.apache.http.client.RedirectStrategy() {
            @Override
            boolean isRedirected(HttpRequest httpRequest, HttpResponse httpResponse, HttpContext httpContext) {
                return false
            }

            @Override
            org.apache.http.client.methods.HttpUriRequest getRedirect(HttpRequest httpRequest, HttpResponse httpResponse, HttpContext httpContext) {
                return null
            }
        })
        return httpclient
    }

    Object run() {
        HttpServletRequest request = RequestContext.currentContext.getRequest();
        Header[] headers = buildOAuth2RequestHeaders(request)
        String verb = "GET";
        HttpClient httpclient = CLIENT.get()

        String uri = "/oauth2-server-php/public/checktoken.php"

        try {
            HttpResponse response = validate(httpclient, verb, uri, request, headers)
            if (Debug.debugRequest()) {
                response.getAllHeaders()?.each { Header header ->
                    Debug.addRequestDebug("OAUTH2_RESPONSE:: < ${header.name}, ${header.value}")
                }
            }
            RequestContext ctx = RequestContext.getCurrentContext();
            if(200 != response.getStatusLine().statusCode){
                ctx.getResponse().addHeader("WWW-Authenticate", response.getFirstHeader("WWW-Authenticate").getValue().toString());
                ctx.setResponseStatusCode(response.getStatusLine().statusCode);
                ctx.setResponseBody(response.getEntity().getContent().getText())
                ctx.sendZuulResponse = false
            } else {
                if (Debug.debugRequest()) {
                    debugResponseEntity(response.getEntity().getContent())
                }
                response.getAllHeaders()?.each { Header header ->
                    if(header.name.toLowerCase().startsWith("x-api-")){
                        ctx.addZuulRequestHeader(header.name, header.value)
                    }
                }
            }
        } catch (Exception e) {
            throw e;
        }
        return null
    }

    InputStream debugResponseEntity(InputStream inputStream) {
        if (Debug.debugRequestHeadersOnly()) return inputStream
        if (inputStream == null) return null
        String entity = inputStream.getText()
        Debug.addRequestDebug("OAUTH2_RESPONSE:: < ${entity}")
        return new ByteArrayInputStream(entity.bytes)
    }

    def void debug(HttpHost httpHost, String verb, String uri, Header[] headers) {

        if (Debug.debugRequest()) {

            Debug.addRequestDebug("ZUUL_OAUTH2:: host=${httpHost}")

            headers.each {
                Debug.addRequestDebug("ZUUL_OAUTH2:: > ${it.name}  ${it.value}")
            }

            Debug.addRequestDebug("ZUUL_OAUTH2:: > ${verb}  ${uri} HTTP/1.1")
        }
    }

    def HttpResponse validate(HttpClient httpclient, String verb, String uri, HttpServletRequest request, Header[] headers) {
        String queryString = request.getHeader("X-Acces-Token".toLowerCase())

        org.apache.http.HttpHost httpHost = new HttpHost("localhost", 3000, "http")

        uri += "?access_token=" + queryString

        debug(httpHost, verb, uri, headers)

        org.apache.http.HttpRequest httpRequest = new BasicHttpRequest(verb, uri)

        try {
            httpRequest.setHeaders(headers)
            HttpResponse oauthResponse = validateRequest(httpclient, httpHost, httpRequest)
            return oauthResponse
        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
//            httpclient.getConnectionManager().shutdown();
        }

    }

    HttpResponse validateRequest(HttpClient httpclient, HttpHost httpHost, HttpRequest httpRequest) {
        return httpclient.execute(httpHost, httpRequest);
    }

    def Header[] buildOAuth2RequestHeaders(HttpServletRequest request) {

        def headers = new ArrayList()
        if (RequestContext.currentContext.responseGZipped) {
            headers.add(new BasicHeader("accept-encoding", "deflate, gzip"))
        }

        headers.add(new BasicHeader("host", "oauth2-server-php.local"))

        return headers
    }

}


