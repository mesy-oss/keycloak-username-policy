package li.mesy.keycloakusernamepolicy.action;

import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Validates usernames based on username policies specified by an administrator
 *
 * @author Lukas Schulte Pelkum
 * @version 0.1.0
 * @since 0.1.0
 */
public class UsernameValidatingFormAction implements FormAction {

    @Override
    public void buildPage(final FormContext context, final LoginFormsProvider form) {
    }

    @Override
    public void validate(final ValidationContext context) {
        // Load and parse the policy configuration values
        final Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        final String whitelist = config.getOrDefault("whitelist", "");
        final String blacklist = config.getOrDefault("blacklist", "");
        final int minLength = this.parseUIntOrElse(config.getOrDefault("min_length", ""), -1);
        final int maxLength = this.parseUIntOrElse(config.getOrDefault("max_length", ""), -1);

        // Load the form data, extract the username field and prepare the error stack
        final MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        final String username = formData.getFirst(RegistrationPage.FIELD_USERNAME);
        final List<FormMessage> errors = new ArrayList<>();

        // Check the username against the white-/blacklist
        if (!whitelist.isEmpty()) {
            if (Arrays.stream(username.split("")).anyMatch(part -> !whitelist.contains(part))) {
                errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.INVALID_USERNAME));
            }
        } else if (!blacklist.isEmpty()) {
            if (Arrays.stream(username.split("")).anyMatch(blacklist::contains)) {
                errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.INVALID_USERNAME));
            }
        }

        // Validate the length of the username
        if (username.length() < minLength) {
            errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.INVALID_USERNAME));
        }
        if (maxLength > 0 && username.length() > maxLength) {
            errors.add(new FormMessage(RegistrationPage.FIELD_USERNAME, Messages.INVALID_USERNAME));
        }

        // Cancel if any errors occurred
        if (!errors.isEmpty()) {
            context.validationError(formData, errors);
            return;
        }
        context.success();
    }

    @Override
    public void success(final FormContext context) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(final KeycloakSession session, final RealmModel realm, final UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(final KeycloakSession session, final RealmModel realm, final UserModel user) {
    }

    @Override
    public void close() {
    }

    private int parseUIntOrElse(final String toParse, final int fallback) {
        try {
            return Integer.parseUnsignedInt(toParse);
        } catch (final NumberFormatException exception) {
            return fallback;
        }
    }

}
