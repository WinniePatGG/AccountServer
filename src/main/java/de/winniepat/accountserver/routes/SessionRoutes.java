package de.winniepat.accountserver.routes;

import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.token.Token;
import de.craftsblock.cnet.modules.security.auth.token.TokenPermission;
import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftsnet.api.http.*;
import de.craftsblock.craftsnet.api.http.annotations.RequestMethod;
import de.craftsblock.craftsnet.api.http.annotations.RequireBody;
import de.craftsblock.craftsnet.api.http.annotations.RequireHeaders;
import de.craftsblock.craftsnet.api.http.annotations.Route;
import de.craftsblock.craftsnet.api.http.body.bodies.JsonBody;
import de.craftsblock.craftsnet.api.session.Session;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import de.winniepat.accountserver.utils.OneTimeToken;

import java.util.concurrent.ConcurrentHashMap;

@AutoRegister
@Route("/v1/account/session")
public class SessionRoutes implements RequestHandler {

    protected static final ConcurrentHashMap<Long, OneTimeToken> tokens = new ConcurrentHashMap<>();

    @Route("/login")
    @RequireBody(JsonBody.class)
    @RequestMethod(HttpMethod.POST)
    public Json handleLogin(Exchange exchange) {
        final Request request = exchange.request();
        final Response response = exchange.response();
        Json body = request.getBody().getAsJsonBody().getBody();

        if (!body.contains("login.type") || !body.getString("login.type").equalsIgnoreCase("one_time_token")) {
            response.setCode(400);
            return Json.empty()
                    .set("status", "400")
                    .set("message", "Invalid login type %s!".formatted(body.getString("login.type")));
        }

        if (!body.contains("login.id") || !body.contains("login.token")) {
            response.setCode(400);
            return Json.empty()
                    .set("status", 400)
                    .set("message", "Invalid login payload!");
        }

        long id = body.getLong("login.id");
        if (!tokens.containsKey(id)) {
            response.setCode(400);
            return Json.empty()
                    .set("status", "400")
                    .set("message", "Invalid login token!");
        }

        OneTimeToken oneTimeToken = tokens.remove(id);
        String loginToken = body.getString("login.token");
        if (!oneTimeToken.check(loginToken)) {
            response.setCode(400);
            return Json.empty()
                    .set("status", "400")
                    .set("message", "Invalid login token!");
        }

        TokenPermission  session = TokenPermission.of("/v1/account/session/(?:logout|check)", ".*", HttpMethod.DELETE, HttpMethod.GET);
        TokenPermission cdn = TokenPermission.of("^/v1/cdn/(?!meta.*).*$", ".*", HttpMethod.GET);

        byte[] token = CNetSecurity.getTokenManager().generateToken(session, cdn).getKey();
        Json result = Json.empty().set("status", "200").set("token", PassphraseUtils.stringify(token));
        PassphraseUtils.erase(token);
        Json.empty().set("status", "200").set("token", token);
        return result;
    }

    @Route("/logout")
    @RequireHeaders("Authorization")
    @RequestMethod(HttpMethod.DELETE)
    public Json handleLogout(Exchange exchange) {
        final Session session = exchange.session();

        Token token = session.getAsType("auth.token", Token.class);
        CNetSecurity.getTokenManager().unregisterToken(token);

        return Json.empty().set("status", "200").set("message", "Token revoked");
    }

    @Route("/check")
    @RequestMethod(HttpMethod.GET)
    @RequireHeaders("Authorization")
    public Json handleCheck(Exchange exchange) {
        final Request request = exchange.request();
        final Response response = exchange.response();
        return Json.empty().set("status", "200").set("message", "Token is valid");
    }
}
