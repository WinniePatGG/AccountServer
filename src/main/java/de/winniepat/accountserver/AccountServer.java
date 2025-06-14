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
                .withAddonSystem(ActivateType.DISABLED)
                .withFileLogger(ActivateType.DISABLED)
                .withDebug(true)
                .withArgs(args)
                .build();
    }

    @Override
    public void onEnable() {
        TokenAuthAdapter tokenAuthAdapter = new TokenAuthAdapter();
        tokenAuthAdapter.enable(TokenAuthType.HEADER);
        CNetSecurity.getDefaultAuthChain().append(tokenAuthAdapter);
        CNetSecurity.getDefaultAuthChain().addExclusion("/v1/account/session/login");

        CNetSecurity.getRateLimitManager().register(new IPRateLimitAdapter(500));
        CNetSecurity.getRateLimitManager().register(new TokenRateLimitAdapter(60));
    }
}
