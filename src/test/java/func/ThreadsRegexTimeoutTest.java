package func;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreadsRegexTimeoutTest {

    /** 正常正则应在资源边界内保持原有匹配结果。 */
    @Test
    void matchesNormalRegexWithinDeadline() {
        assertTrue(threads.findWithTimeout(
                Pattern.compile("RouteVulScan"),
                "prefix RouteVulScan suffix",
                TimeUnit.SECONDS.toNanos(1)
        ));
    }

    /** 灾难性回溯必须由带截止时间的字符序列主动终止。 */
    @Test
    void stopsCatastrophicBacktrackingAtDeadline() {
        String adversarialInput = "a".repeat(50_000) + "!";

        assertThrows(
                threads.RegexTimeoutException.class,
                () -> threads.findWithTimeout(
                        Pattern.compile("(a+)+$"),
                        adversarialInput,
                        TimeUnit.MILLISECONDS.toNanos(1)
                )
        );
    }
}
