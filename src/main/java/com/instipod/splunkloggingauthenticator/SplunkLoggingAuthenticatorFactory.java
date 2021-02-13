package com.instipod.splunkloggingauthenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Collections;
import java.util.List;

public class SplunkLoggingAuthenticatorFactory implements AuthenticatorFactory {
    protected static final String CONFIG_HOSTNAME = "syslogHostname";
    protected static final String CONFIG_SERVER = "serverHostname";
    protected static final String CONFIG_PORT = "serverPort";
    protected static final String CONFIG_TOKEN = "serverToken";
    protected static final String CONFIG_EVENTTYPE = "eventType";
    protected static final String CONFIG_MESSAGE = "syslogMessage";
    protected static final String CONFIG_USESSL = "useSSL";

    private static final String PROVIDER_ID = "splunkLoggingAuthenticator";
    private static List<ProviderConfigProperty> commonConfig;

    static {
        commonConfig = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
                .property().name(CONFIG_HOSTNAME).label("Local Hostname Identifier").helpText("Source hostname in syslog messages").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(CONFIG_SERVER).label("Splunk Server").helpText("Hostname or IP address of the server to send logs to").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(CONFIG_PORT).label("HTTP Port").helpText("Port to send logs to (default 8088)").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(CONFIG_USESSL).label("Use SSL").helpText("Send logs over HTTP or HTTPS").type(ProviderConfigProperty.BOOLEAN_TYPE).add()
                .property().name(CONFIG_TOKEN).label("Server Token").helpText("Security key used to authorize the request").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(CONFIG_EVENTTYPE).label("Event Type").helpText("Category for the log message").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(CONFIG_MESSAGE).label("Message").helpText("Message to send (supports variables)").type(ProviderConfigProperty.STRING_TYPE).add()
                .build()
        );
    }

    @Override
    public String getDisplayType() {
        return "Splunk Log Message";
    }

    @Override
    public String getReferenceCategory() {
        return "generic";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Sends a Splunk log as part of an authentication flow.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return commonConfig;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return SplunkLoggingAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
        //not used
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        //not used
    }

    @Override
    public void close() {
        //not used
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
