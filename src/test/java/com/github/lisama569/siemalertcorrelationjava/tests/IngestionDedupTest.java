package com.github.lisama569.siemalertcorrelationjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.siemalertcorrelationjava.engine.ingest.IngestionService;
import com.github.lisama569.siemalertcorrelationjava.model.event.IngestionOutcome;
import com.github.lisama569.siemalertcorrelationjava.model.event.RawEvent;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestFixtures;
import com.github.lisama569.siemalertcorrelationjava.tests.support.TestLogger;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/** 接入去重测试：同事件重复提交不重复计数；并发提交只有一个胜出。 */
class IngestionDedupTest {

    private IngestionService service() {
        Clock clock = Clock.fixed(Instant.ofEpochMilli(TestFixtures.T0 + 1000L), ZoneOffset.UTC);
        return new IngestionService(
                new com.github.lisama569.siemalertcorrelationjava.engine.ingest.EventNormalizer(), clock);
    }

    @Test
    void duplicateSubmissionIsCountedOnce() {
        TestLogger.section("IngestionDedupTest.duplicateSubmissionIsCountedOnce");
        IngestionService svc = service();
        RawEvent event = TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED",
                TestFixtures.iso(TestFixtures.T0), "dup-1", "alice", "10.0.0.11", "10.0.0.1", null);

        IngestionOutcome first = svc.ingest(event);
        IngestionOutcome second = svc.ingest(event);
        IngestionOutcome third = svc.ingest(event);
        TestLogger.input("提交次数", 3);
        TestLogger.basis("eventId", first.eventId());
        TestLogger.state("accepted 计数 / 各次标记",
                svc.acceptedCount() + " / first=" + first.duplicate()
                        + " second=" + second.duplicate() + " third=" + third.duplicate());

        assertTrue(first.accepted() && !first.duplicate());
        assertTrue(second.accepted() && second.duplicate());
        assertTrue(third.accepted() && third.duplicate());
        assertEquals(1, svc.acceptedCount());
    }

    @Test
    void rejectedEventCanBeResubmittedAfterFix() {
        TestLogger.section("IngestionDedupTest.rejectedEventCanBeResubmittedAfterFix");
        IngestionService svc = service();
        RawEvent bad = TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED", "bad-time",
                "fix-1", "alice", "10.0.0.11", "10.0.0.1", null);
        IngestionOutcome rejected = svc.ingest(bad);
        TestLogger.basis("首次提交", rejected.reason().code());
        assertFalse(rejected.accepted());

        RawEvent fixed = TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED",
                TestFixtures.iso(TestFixtures.T0), "fix-1", "alice", "10.0.0.11", "10.0.0.1", null);
        IngestionOutcome accepted = svc.ingest(fixed);
        TestLogger.state("修正后提交", accepted.accepted() + " count=" + svc.acceptedCount());
        assertTrue(accepted.accepted());
        assertEquals(1, svc.acceptedCount());
    }

    @Test
    void concurrentSubmissionsDeduplicateExactlyOnce() throws Exception {
        TestLogger.section("IngestionDedupTest.concurrentSubmissionsDeduplicateExactlyOnce");
        IngestionService svc = service();
        RawEvent event = TestFixtures.raw("AUTH_SERVICE", "LOGIN_FAILED",
                TestFixtures.iso(TestFixtures.T0), "race-1", "alice", "10.0.0.11", "10.0.0.1", null);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<IngestionOutcome>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> svc.ingest(event));
        }
        List<Future<IngestionOutcome>> futures = pool.invokeAll(tasks);
        long firstCount = 0;
        long dupCount = 0;
        for (Future<IngestionOutcome> f : futures) {
            IngestionOutcome o = f.get();
            if (o.duplicate()) {
                dupCount++;
            } else {
                firstCount++;
            }
        }
        pool.shutdown();
        TestLogger.input("并发线程", threads);
        TestLogger.state("首次/重复", firstCount + "/" + dupCount + " 唯一计数=" + svc.acceptedCount());
        assertEquals(1, firstCount);
        assertEquals(threads - 1, dupCount);
        assertEquals(1, svc.acceptedCount());
    }
}
