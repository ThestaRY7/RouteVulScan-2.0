package utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BoundedSetTest {

    /** 容量满后应只淘汰最早元素，并保留最近加入的去重键。 */
    @Test
    void evictsTheOldestElementAtCapacity() {
        BoundedSet<String> values = new BoundedSet<String>(2);

        assertTrue(values.add("first"));
        assertTrue(values.add("second"));
        assertTrue(values.add("third"));

        assertFalse(values.contains("first"));
        assertTrue(values.contains("second"));
        assertTrue(values.contains("third"));
    }

    /** 重复添加不能改变集合容量或触发额外淘汰。 */
    @Test
    void duplicateAddDoesNotEvictAnotherElement() {
        BoundedSet<String> values = new BoundedSet<String>(2);
        values.add("first");
        values.add("second");

        assertFalse(values.add("second"));
        assertTrue(values.contains("first"));
        assertTrue(values.contains("second"));
    }

    /** 通过 Set 删除和迭代器删除都必须作用于底层集合，不能只修改快照。 */
    @Test
    void supportsSetRemovalContract() {
        BoundedSet<String> values = new BoundedSet<String>(3);
        values.add("first");
        values.add("second");
        values.add("third");

        assertTrue(values.remove("first"));
        java.util.Iterator<String> iterator = values.iterator();
        assertEquals("second", iterator.next());
        iterator.remove();

        assertFalse(values.contains("first"));
        assertFalse(values.contains("second"));
        assertTrue(values.contains("third"));
    }
}
