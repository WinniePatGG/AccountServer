package de.winniepat.accountserver;

import de.craftsblock.cnet.modules.security.AddonEntrypoint;
import de.craftsblock.cnet.modules.security.CNetSecurity;
import de.craftsblock.cnet.modules.security.auth.token.adapter.TokenAuthAdapter;
import de.craftsblock.cnet.modules.security.auth.token.adapter.TokenAuthType;
import de.craftsblock.cnet.modules.security.ratelimit.builtin.IPRateLimitAdapter;
import de.craftsblock.cnet.modules.security.ratelimit.builtin.TokenRateLimitAdapter;
import de.craftsblock.craftsnet.CraftsNet;
import de.craftsblock.craftsnet.addon.Addon;
import de.craftsblock.craftsnet.addon.meta.annotations.Depends;
import de.craftsblock.craftsnet.addon.meta.annotations.Meta;
import de.craftsblock.craftsnet.builder.ActivateType;

import java.io.IOException;

@Meta(name = "AccountServer")
@Depends(AddonEntrypoint.class)
public class AccountServer extends Addon {

    public static void main(String[] args) throws IOException {
        CraftsNet.create(AccountServer.class)
                .withFileLogger(ActivateType.DISABLED)
                .withDebug(true)
                .withArgs(args)
                .withWebSocketServer(8000)
                .withWebServer(8765)
                .build();
    }

    @Override
    public void onEnable() {
        TokenAuthAdapter adapter = new TokenAuthAdapter();
        adapter.enable(TokenAuthType.HEADER);
        adapter.enable(TokenAuthType.COOKIE, "sess_token");
        adapter.enable(TokenAuthType.SESSION, "session.token");
        CNetSecurity.getDefaultAuthChain().append(adapter);

        CNetSecurity.getDefaultAuthChain().addExclusion("/v1/account/session/login");
        CNetSecurity.getDefaultAuthChain().addExclusion("^/v1/minecraft/session/challenge/(?:create|complete)$");

        CNetSecurity.getRateLimitManager().register(new IPRateLimitAdapter(500));
        CNetSecurity.getRateLimitManager().register(new TokenRateLimitAdapter(60));
    }
}
