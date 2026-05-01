package burp;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

public class I18n {
    public static final String DEFAULT_LANGUAGE = "zh_CN";
    public static final String ENGLISH_LANGUAGE = "en_US";

    private static final String BUNDLE_NAME = "i18n.messages";
    private static Locale locale = Locale.SIMPLIFIED_CHINESE;
    private static ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_NAME, locale);

    public static synchronized void setLanguage(String language) {
        locale = localeFor(language);
        bundle = ResourceBundle.getBundle(BUNDLE_NAME, locale);
    }

    public static synchronized String language() {
        if (Locale.US.getLanguage().equals(locale.getLanguage())) {
            return ENGLISH_LANGUAGE;
        }
        return DEFAULT_LANGUAGE;
    }

    public static synchronized String t(String key, Object... args) {
        String pattern;
        try {
            pattern = bundle.getString(key);
        } catch (MissingResourceException e) {
            pattern = key;
        }
        if (args == null || args.length == 0) {
            return pattern;
        }
        return MessageFormat.format(pattern, args);
    }

    private static Locale localeFor(String language) {
        if (ENGLISH_LANGUAGE.equalsIgnoreCase(language) || "en".equalsIgnoreCase(language)) {
            return Locale.US;
        }
        return Locale.SIMPLIFIED_CHINESE;
    }
}
