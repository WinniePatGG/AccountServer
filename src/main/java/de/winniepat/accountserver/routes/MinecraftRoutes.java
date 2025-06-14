package de.winniepat.accountserver.routes;

import de.craftsblock.craftscore.json.Json;
import de.craftsblock.craftscore.json.JsonParser;
import de.craftsblock.craftscore.utils.id.Snowflake;
import de.craftsblock.craftsnet.api.http.*;
import de.craftsblock.craftsnet.api.http.annotations.RequestMethod;
import de.craftsblock.craftsnet.api.http.annotations.RequireBody;
import de.craftsblock.craftsnet.api.http.annotations.Route;
import de.craftsblock.craftsnet.api.http.body.bodies.JsonBody;
import de.craftsblock.craftsnet.autoregister.meta.AutoRegister;
import de.craftsblock.craftsnet.utils.PassphraseUtils;
import de.winniepat.accountserver.utils.OneTimeToken;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

@AutoRegister
@Route("/v1/minecraft/session/challenge")
public class MinecraftRoutes implements RequestHandler {

    private final MessageDigest messageDigest;
    private final KeyPairGenerator keyPairGenerator;
    private final KeyGenerator keyGenerator;

    private final HttpClient httpClient;

    public MinecraftRoutes() throws NoSuchAlgorithmException {
        this.messageDigest = MessageDigest.getInstance("SHA-1");
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        this.keyGenerator = KeyGenerator.getInstance("AES");

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @Route("/create")
    @RequestMethod(HttpMethod.GET)
    public Json handleChallengeCreate(Exchange exchange) {
        KeyPair pair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();

        SecretKey secretKey = keyGenerator.generateKey();

        byte[] data;
        synchronized (messageDigest) {
            messageDigest.update("".getBytes(StandardCharsets.ISO_8859_1));
            messageDigest.update(secretKey.getEncoded());
            messageDigest.update(secretKey.getEncoded());

            data = messageDigest.digest();
        }
        return Json.empty()
                .set("status", "200")
                .set("token", new BigInteger(data).toString(16));
    }

    @Route("/complete")
    @RequireBody(JsonBody.class)
    @RequestMethod(HttpMethod.POST)
    public Json handleComplete(Exchange exchange) throws IOException, InterruptedException {
        final Request request = exchange.request();
        final Response response = exchange.response();
        final Json body = request.getBody().getAsJsonBody().getBody();

        if (!body.contains("name") || !body.contains("token")) {
            response.setCode(400);
            return Json.empty()
                    .set("status", "400")
                    .set("message", "Malformed body! Ensure that the name and token is present");
        }

        String name = body.getString("name");
        String serverID = body.getString("token");

        String url = "https://sessionserver.mojang.com/session/minecraft/hasJoined?username=%s&serverId=%s".formatted(
                name, serverID
        );

        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(url)).GET().build();
        HttpResponse<Void> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.discarding());

        if (httpResponse.statusCode() != 204) {
            response.setCode(400);
            return Json.empty()
                    .set("status", "400")
                    .set("message", "You have failed the challenge!");
        }

        byte[] secret = PassphraseUtils.generateSecure(52, 72, true);

        Optional<UUID> uuid = requestsUUID(name);
        if (uuid.isEmpty()) {
            response.setCode(400);
            return Json.empty()
                    .set("status", "400")
                    .set("message", "Can not convert the name to a uuid!");
        }

        long id = Snowflake.generate();
        OneTimeToken token = new OneTimeToken(secret, System.currentTimeMillis() + 1000 * 10, uuid);
        SessionRoutes.tokens.put(id, token);

        Json result = Json.empty()
                .set("status", "200")
                .set("login.type", "one_time_token")
                .set("login.id", id)
                .set("login.secret", PassphraseUtils.stringify(secret));
        PassphraseUtils.erase(secret);
        return result;
    }

    private Optional<UUID> requestsUUID(String username) throws IOException, InterruptedException {
        String url = "https://api.mojang.com/users/profiles/minecraft/%s".formatted(username);
        HttpRequest httpRequest = HttpRequest.newBuilder(URI.create(url)).GET().build();
        HttpResponse<String> httpResponse = httpClient.send(
                httpRequest, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );

        Json json = JsonParser.parse(httpResponse.body());
        if (!json.contains("id")) return Optional.empty();

        String uuid = json.getString("id").replaceFirst(
                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                "$1-$2-$3-$4-$5"
        );
        return Optional.of(UUID.fromString(uuid));
    }

}
