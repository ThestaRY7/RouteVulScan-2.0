package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BurpExtenderMetricsTest {

    /** 取消扫描必须立即清零运行中任务计数，不能让已取消任务永久残留在进度栏。 */
    @Test
    void cancelClearsRunningTaskCount() {
        BurpExtender burp = new BurpExtender();
        burp.noteTaskStarted();

        burp.cancelActiveScans();

        assertEquals(0, burp.getRunningTaskCount());
        burp.ThreadPool.shutdownNow();
    }

    /** 活跃扫描是实时状态，重置累计指标时不能清零并误减后续新扫描。 */
    @Test
    void resetMetricsPreservesActiveScanGauge() {
        BurpExtender burp = new BurpExtender();
        burp.beginScanSession();

        burp.resetScanMetrics();
        assertEquals(1, burp.getActiveScanCount());

        burp.endScanSession();
        assertEquals(0, burp.getActiveScanCount());
    }
}
