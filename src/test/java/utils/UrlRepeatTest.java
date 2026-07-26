package utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UrlRepeatTest {

    /** 参数归一化只清空查询值，不能误替换路径或丢失锚点。 */
    @Test
    void normalizesOnlyQueryParameterValues() {
        UrlRepeat repeat = new UrlRepeat(10);

        assertEquals(
                "https://example.test/value?name=&flag=#part",
                repeat.RemoveUrlParameterValue("https://example.test/value?name=value&flag#part")
        );
    }

    /** 去重窗口满后应允许最早 URL 再次进入扫描流程。 */
    @Test
    void boundsRecordedUrls() {
        UrlRepeat repeat = new UrlRepeat(2);
        repeat.addMethodAndUrl("GET", "https://example.test/first");
        repeat.addMethodAndUrl("GET", "https://example.test/second");
        repeat.addMethodAndUrl("GET", "https://example.test/third");

        assertFalse(repeat.check("GET", "https://example.test/first"));
        assertTrue(repeat.check("GET", "https://example.test/second"));
        assertTrue(repeat.check("GET", "https://example.test/third"));
    }
}
