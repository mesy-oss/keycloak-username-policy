package li.mesy.keycloakusernamepolicy.action;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

/**
 * Provides the {@link UsernameValidatingFormAction} to validate usernames
 *
 * @author Lukas Schulte Pelkum
 * @version 0.1.0
 * @since 0.1.0
 */
public class UsernameValidatingFormActionFactory implements FormActionFactory {

    // We use ONE instance here as there is no point in creating one for every form submit
    private final UsernameValidatingFormAction action = new UsernameValidatingFormAction();

    @Override
    public String getDisplayType() {
        return "Enhanced Username Validation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "This further validates the username based on passed policies.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(
                new ProviderConfigProperty(
                        "whitelist",
                        "Character Whitelist",
                        "If not empty, only characters listed here are allowed for usernames.",
                        ProviderConfigProperty.STRING_TYPE,
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                ),
                new ProviderConfigProperty(
                        "blacklist",
                        "Character Blacklist",
                        "If not overridden by whitelist, all characters listed here are NOT allowed for usernames.",
                        ProviderConfigProperty.STRING_TYPE,
                        ""
                ),
                new ProviderConfigProperty(
                        "min_length",
                        "Minimum Length",
                        "The minimum amount of characters a username has to have.",
                        ProviderConfigProperty.STRING_TYPE,
                        "3"
                ),
                new ProviderConfigProperty(
                        "max_length",
                        "Maximum Length",
                        "The maximum amount of characters a username may have.",
                        ProviderConfigProperty.STRING_TYPE,
                        ""
                )
        );
    }

    @Override
    public FormAction create(final KeycloakSession session) {
        return this.action;
    }

    @Override
    public void init(final Config.Scope config) {
    }

    @Override
    public void postInit(final KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "enhanced-username-validator";
    }

}
