package burp;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BfuncTest {

    /**
     * 状态码解析应支持空格、列表和区间，同时保持稳定顺序并去重。
     */
    @Test
    void parsesStatusCodeListsAndRanges() {
        assertEquals(
                Arrays.asList(200, 201, 202, 204),
                new ArrayList<Integer>(Bfunc.StatusCodeProc("200, 201-202, 204, 200"))
        );
    }

    /**
     * 非法状态码不能在扫描线程中以未说明的数字异常形式失败。
     */
    @Test
    void rejectsMalformedStatusCodes() {
        assertThrows(IllegalArgumentException.class, () -> Bfunc.StatusCodeProc("200,"));
        assertThrows(IllegalArgumentException.class, () -> Bfunc.StatusCodeProc("500-400"));
        assertThrows(IllegalArgumentException.class, () -> Bfunc.StatusCodeProc("99"));
        assertThrows(IllegalArgumentException.class, () -> Bfunc.StatusCodeProc(null));
    }
}
