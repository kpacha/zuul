import com.netflix.zuul.ZuulFilter
import com.netflix.zuul.context.RequestContext
import redis.clients.jedis.Jedis
import redis.clients.jedis.JedisPool
import redis.clients.jedis.JedisPoolConfig

/**
 * @author kpacha
 */
class QoSFilter extends ZuulFilter {

    private static final String HIGHT_PRIORITY_TOKEN = "abcdefghijklmnopqrstuvwxyz"
    private static final JedisPool JEDIS_POOL = new JedisPool(new JedisPoolConfig(), "localhost")
    private static final Long MAX_RATE = 10l
    private static final int RATE_TTL = 30
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
            RequestContext.getCurrentContext().request.getHeader("X-Priority".toLowerCase())
        )
    }

    @Override
    Object run() {
        RequestContext ctx = RequestContext.getCurrentContext()

        String uri = ctx.request.getRequestURI()
        if (ctx.requestURI != null) {
            uri = ctx.requestURI
        }
        if (uri == null) uri = "/"

        def matcher = PATTERN.matcher(uri)
        if(matcher.matches()){
            String ipAddress = ctx.request.getHeader("X-FORWARDED-FOR")
            if (ipAddress == null) {
                ipAddress = ctx.request.getRemoteAddr()
            }

            Map<String, String> zuulHeaders = ctx.getZuulRequestHeaders()
            String tag = matcher[0][1] + "-" +
                zuulHeaders.get("X-Api-User".toLowerCase()) + "-" +
                zuulHeaders.get("X-Api-Client".toLowerCase()) + "-" +
                ipAddress

            Jedis jedis = JEDIS_POOL.getResource()
            def rate = jedis.incr(tag)
            if(1l == rate){
                jedis.expire(tag, RATE_TTL)
            }
            ctx.addZuulResponseHeader("X-RateLimit-Tag", tag)
            ctx.addZuulResponseHeader("X-RateLimit-Limit", String.valueOf(MAX_RATE))
            ctx.addZuulResponseHeader("X-RateLimit-Remaining", String.valueOf(MAX_RATE - rate))
            ctx.addZuulResponseHeader("X-RateLimit-TTL", String.valueOf(jedis.ttl(tag)))
            if(rate >= MAX_RATE) {
                ctx.setResponseStatusCode(403);
                ctx.setResponseBody("{\"message\": \"API rate limit exceeded for [" + tag + "]. Please, leash your eager client!\"}")
                ctx.setSendZuulResponse(false)
            }
            jedis.close()
        }

    }

}
