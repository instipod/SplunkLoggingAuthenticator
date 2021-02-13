package com.instipod.splunkloggingauthenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;

public class SyslogUtils {
    public static String resolveMessage(AuthenticationFlowContext context, String message) {
        String original = message;

        UserModel user = null;
        try {
            user = context.getUser();
        } catch (Exception ex) { }

        try {
            message = message.replace("%userid%", user.getId());
        } catch (Exception ex) {
            message = message.replace("%userid%", "");
        }
        try {
            message = message.replace("%username%", user.getUsername());
        } catch (Exception ex) {
            message = message.replace("%username%", "");
        }
        try {
            message = message.replace("%email%", user.getEmail());
        } catch (Exception ex) {
            message = message.replace("%email%", "");
        }
        try {
            message = message.replace("%firstname%", user.getFirstName());
        } catch (Exception ex) {
            message = message.replace("%firstname%", "");
        }
        try {
            message = message.replace("%lastname%", user.getLastName());
        } catch (Exception ex) {
            message = message.replace("%lastname%", "");
        }
        try {
            message = message.replace("%ipaddress%", context.getConnection().getRemoteAddr());
        } catch (Exception ex) {
            message = message.replace("%ipaddress%", "");
        }
        try {
            message = message.replace("%clientid%", context.getAuthenticationSession().getClient().getId());
        } catch (Exception ex) {
            message = message.replace("%clientid%", "");
        }
        try {
            message = message.replace("%clientname%", context.getAuthenticationSession().getClient().getName());
        } catch (Exception ex) {
            message = message.replace("%clientname%", "");
        }
        try {
            message = message.replace("%clientdesc%", context.getAuthenticationSession().getClient().getDescription());
        } catch (Exception ex) {
            message = message.replace("%clientdesc%", "");
        }
        try {
            message = message.replace("%attempteduser%", context.getAuthenticationSession().getAuthNote("ATTEMPTED_USERNAME"));
        } catch (Exception ex) {
            message = message.replace("%attempteduser%", "");
        }
        try {
            message = message.replace("%realmid%", context.getRealm().getId());
        } catch (Exception ex) {
            message = message.replace("%realmid%", "");
        }
        try {
            message = message.replace("%realmname%", context.getRealm().getName());
        } catch (Exception ex) {
            message = message.replace("%realmname%", "");
        }

        return message;
    }
}
