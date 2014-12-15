import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.context.RequestContext
import redis.clients.jedis.Jedis
import redis.clients.jedis.JedisPool
import redis.clients.jedis.JedisPoolConfig

/**
 * @author kpacha
 */
class QoSFilter extends ZuulFilter {

    private static final String HIGHT_PRIORITY_HEADER = "x-priority"
    private static final String HIGHT_PRIORITY_TOKEN = "abcdefghijklmnopqrstuvwxyz"
    private static final JedisPool JEDIS_POOL = new JedisPool(new JedisPoolConfig(), "localhost")
    private static final Long MAX_RATE = 10l
    private static final int RATE_TTL = 30
    private static final int ERROR_CODE = 403
    private static final PATTERN = ~/\/(.*)\/.*/

    @Override
    int filterOrder() {
        return 15
    }

    @Override
    String filterType() {
        return "pre"
    }

    @Override
    boolean shouldFilter() {
        return !HIGHT_PRIORITY_TOKEN.equals(
            RequestContext.getCurrentContext().request.getHeader(HIGHT_PRIORITY_HEADER)
        )
    }

    @Override
    Object run() {
        RequestContext ctx = RequestContext.getCurrentContext()

        def matcher = PATTERN.matcher(getUri(ctx))
        if(matcher.matches()){
            String tag = getTag(ctx, matcher[0][1])

            if(checkRate(ctx, tag) >= MAX_RATE) {
                ctx.setResponseStatusCode(ERROR_CODE);
                ctx.setResponseBody("{\"message\": \"API rate limit exceeded for [" + tag + "]. Please, leash your eager client!\"}")
                ctx.setSendZuulResponse(false)
            }
        }

    }

    private String getUri(RequestContext ctx) {
        String uri = ctx.request.getRequestURI()
        if (ctx.requestURI != null) uri = ctx.requestURI
        if (uri == null) uri = "/"
        uri
    }

    private String getIpAddress(RequestContext ctx) {
        String ipAddress = ctx.request.getHeader("X-FORWARDED-FOR")
        if (ipAddress == null) ipAddress = ctx.request.getRemoteAddr()
        ipAddress
    }

    private String getTag(RequestContext ctx, String resource) {
        Map<String, String> zuulHeaders = ctx.getZuulRequestHeaders()
        resource + "-" + zuulHeaders.get("X-Api-User".toLowerCase()) + "-" +
            zuulHeaders.get("X-Api-Client".toLowerCase()) + "-" + getIpAddress(ctx)
    }

    private checkRate(RequestContext ctx, String tag) {
        Jedis jedis = JEDIS_POOL.getResource()
        def rate = jedis.incr(tag)
        if(1l == rate) jedis.expire(tag, RATE_TTL)

        ctx.addZuulResponseHeader("X-RateLimit-Tag", tag)
        ctx.addZuulResponseHeader("X-RateLimit-Limit", String.valueOf(MAX_RATE))
        ctx.addZuulResponseHeader("X-RateLimit-Remaining", String.valueOf(MAX_RATE - rate))
        ctx.addZuulResponseHeader("X-RateLimit-TTL", String.valueOf(jedis.ttl(tag)))
        jedis.close()

        rate
    }

}
