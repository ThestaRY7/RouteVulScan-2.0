package yaml;

import burp.Bfunc;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RulesYamlIntegrityTest {
    private static final Set<String> REQUIRED_KEYS = Set.of(
            "id", "type", "loaded", "name", "method", "url", "re", "info", "state"
    );

    /** 发布内置规则必须保持唯一 ID、完整字段、合法状态码与可编译正则。 */
    @Test
    @SuppressWarnings("unchecked")
    void bundledRulesAreValidAndHaveUniqueIds() throws IOException {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        try (InputStream inputStream = RulesYamlIntegrityTest.class.getResourceAsStream("/Rules.yaml")) {
            assertNotNull(inputStream);
            Map<String, Object> yaml = new Yaml(new SafeConstructor(options)).load(inputStream);
            List<Map<String, Object>> rules = (List<Map<String, Object>>) yaml.get("Load_List");
            Set<Object> ids = new HashSet<Object>();

            for (Map<String, Object> rule : rules) {
                assertTrue(rule.keySet().containsAll(REQUIRED_KEYS));
                assertTrue(ids.add(rule.get("id")), "Duplicate rule id: " + rule.get("id"));
                assertTrue(rule.get("loaded") instanceof Boolean);
                assertTrue(rule.get("state") instanceof String);
                Bfunc.StatusCodeProc((String) rule.get("state"));
                Pattern.compile((String) rule.get("re"));
            }
            assertEquals(rules.size(), ids.size());
        }
    }
}
