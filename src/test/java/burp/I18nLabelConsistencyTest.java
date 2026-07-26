package burp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Locale;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

class I18nLabelConsistencyTest {

    /**
     * 每个测试结束后恢复插件默认语言，避免静态语言状态影响其他测试。
     */
    @AfterEach
    void restoreDefaultLanguage() {
        I18n.setLanguage(I18n.DEFAULT_LANGUAGE);
    }

    /**
     * 中文规则列表、编辑器和结果页必须使用同一套字段名称。
     */
    @Test
    void keepsChineseRuleLabelsConsistent() {
        I18n.setLanguage(I18n.DEFAULT_LANGUAGE);
        assertRuleLabelsMatch();
        assertEquals("规则名称", I18n.t("table.rule.name"));
    }

    /**
     * 英文资源与中文资源保持同样的字段映射，切换语言后不能再次出现歧义。
     */
    @Test
    void keepsEnglishRuleLabelsConsistent() {
        I18n.setLanguage(I18n.ENGLISH_LANGUAGE);
        assertRuleLabelsMatch();
        assertEquals("Rule Name", I18n.t("table.rule.name"));
    }

    /** 中英文资源键必须完全一致，避免切换语言后显示原始 key。 */
    @Test
    void keepsTranslationResourceKeysInSync() {
        ResourceBundle chinese = ResourceBundle.getBundle("i18n.messages", Locale.SIMPLIFIED_CHINESE);
        ResourceBundle english = ResourceBundle.getBundle("i18n.messages", Locale.US);

        assertEquals(chinese.keySet(), english.keySet());
    }

    /** 比较规则列表与其他页面中含义相同的字段标签。 */
    private void assertRuleLabelsMatch() {
        assertAll(
                () -> assertEquals(I18n.t("table.rule.name"), I18n.t("form.ruleName")),
                () -> assertEquals(I18n.t("table.rule.name"), I18n.t("table.result.name")),
                () -> assertEquals(I18n.t("table.rule.method"), I18n.t("form.method")),
                () -> assertEquals(I18n.t("table.rule.path"), I18n.t("form.path")),
                () -> assertEquals(I18n.t("table.rule.regex"), I18n.t("form.regex")),
                () -> assertEquals(I18n.t("table.rule.info"), I18n.t("form.info")),
                () -> assertEquals(I18n.t("table.rule.status"), I18n.t("form.statusCodes"))
        );
    }
}
