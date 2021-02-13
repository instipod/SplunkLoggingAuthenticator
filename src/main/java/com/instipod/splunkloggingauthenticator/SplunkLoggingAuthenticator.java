package com.instipod.splunkloggingauthenticator;

import org.jboss.logging.Logger;
import org.json.JSONObject;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class SplunkLoggingAuthenticator implements Authenticator {
    public static final SplunkLoggingAuthenticator SINGLETON = new SplunkLoggingAuthenticator();

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticatorConfigModel config = authenticationFlowContext.getAuthenticatorConfig();
        if (config.getConfig().getOrDefault(SplunkLoggingAuthenticatorFactory.CONFIG_MESSAGE, "").equalsIgnoreCase("")) {
            //no message defined
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        } else {
            JSONObject rootObject = new JSONObject();
            JSONObject event = new JSONObject();

            event.put("ipAddress", authenticationFlowContext.getConnection().getRemoteAddr());
            event.put("clientId", authenticationFlowContext.getAuthenticationSession().getClient().getId());
            event.put("clientName", authenticationFlowContext.getAuthenticationSession().getClient().getName());
            event.put("attemptedUser", authenticationFlowContext.getAuthenticationSession().getAuthNote("ATTEMPTED_USERNAME"));
            if (authenticationFlowContext.getUser() != null) {
                UserModel user = authenticationFlowContext.getUser();
                event.put("userId", user.getId());
                event.put("userUsername", user.getUsername());
                event.put("userEmail", user.getEmail());
                event.put("userIdentified", true);
            } else {
                event.put("userIdentified", false);
            }
            event.put("eventType", config.getConfig().get(SplunkLoggingAuthenticatorFactory.CONFIG_EVENTTYPE));
            event.put("message", SyslogUtils.resolveMessage(authenticationFlowContext, config.getConfig().get(SplunkLoggingAuthenticatorFactory.CONFIG_MESSAGE)));

            rootObject.put("time", Instant.now().getEpochSecond());
            rootObject.put("host", config.getConfig().getOrDefault(SplunkLoggingAuthenticatorFactory.CONFIG_HOSTNAME, "keycloak"));
            rootObject.put("sourcetype", "json_no_timestamp");
            rootObject.put("event", event);

            String jsonOutput = rootObject.toString();
            byte[] out = jsonOutput.getBytes(StandardCharsets.UTF_8);
            int length = out.length;

            String protocol = "http://";
            if (config.getConfig().getOrDefault(SplunkLoggingAuthenticatorFactory.CONFIG_USESSL, "false").equalsIgnoreCase("true")) {
                protocol = "https://";
            }

            try {
                URL url = new URL(protocol + config.getConfig().get(SplunkLoggingAuthenticatorFactory.CONFIG_SERVER) + ":" + config.getConfig().getOrDefault(SplunkLoggingAuthenticatorFactory.CONFIG_PORT, "8088") + "/services/collector");
                URLConnection con = url.openConnection();
                HttpURLConnection http = (HttpURLConnection) con;
                http.setRequestMethod("POST"); // PUT is another valid option
                http.setDoOutput(true);
                http.setConnectTimeout(2);
                http.setReadTimeout(2);
                http.setFixedLengthStreamingMode(length);
                http.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
                http.setRequestProperty("Authorization", "Splunk " + config.getConfig().get(SplunkLoggingAuthenticatorFactory.CONFIG_TOKEN));
                http.connect();
                try (OutputStream os = http.getOutputStream()) {
                    os.write(out);
                }
            } catch (Exception ex) {
                Logger logger = Logger.getLogger(SplunkLoggingAuthenticator.class);
                logger.error("Failed to send log message: Exception " + ex.getMessage());
            }

            authenticationFlowContext.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        //not used
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        //not used
    }

    @Override
    public void close() {
        //not used
    }
}
