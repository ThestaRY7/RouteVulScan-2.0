package UI;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TagsResultRecordTest {

    /**
     * 模拟刷新时从历史记录重建显示行，确认不可变字段不会被清空或重新编号。
     */
    @Test
    void rebuildingTableRowKeepsIdentityAndTimes() {
        Tags.LogEntry historyEntry = new Tags.LogEntry(
                7,
                "测试规则",
                "GET",
                "https://example.test/admin",
                "200",
                "测试说明",
                "123",
                null,
                "example.test",
                "2026-07-24 12:00:00",
                "2026-07-24 12:00:01"
        );

        Tags.TablesData displayedEntry = new Tags.TablesData(historyEntry);

        assertAll(
                () -> assertEquals(7, displayedEntry.id),
                () -> assertEquals("测试规则", displayedEntry.ruleName),
                () -> assertEquals("2026-07-24 12:00:00", displayedEntry.startTime),
                () -> assertEquals("2026-07-24 12:00:01", displayedEntry.endTime)
        );
    }
}
