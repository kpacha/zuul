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

import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.context.RequestContext

/**
 * @author mhawthorne
 */
class PreDecorationFilter extends ZuulFilter {

    @Override
    int filterOrder() {
        return 5
    }

    @Override
    String filterType() {
        return "pre"
    }

    @Override
    boolean shouldFilter() {
        return true;
    }

    @Override
    Object run() {
        RequestContext ctx = RequestContext.getCurrentContext()

        String uri = ctx.request.getRequestURI()
        if (ctx.requestURI != null) {
            uri = ctx.requestURI
        }
        if (uri == null) uri = "/"
        if (uri.startsWith("/token.php") || uri.startsWith("/checktoken.php")) {
            ctx.setRouteHost(new URL("http://localhost:3000/"));
            ctx.addZuulRequestHeader("Host", "oauth2-server-php.local");
        } else {
            // sets origin
            ctx.setRouteHost(new URL("http://www.apache.org/"));
            ctx.addZuulRequestHeader("Host", "www.apache.org");
        }

        // sets custom header to send to the origin
        ctx.addOriginResponseHeader("cache-control", "max-age=3600");
    }

}
