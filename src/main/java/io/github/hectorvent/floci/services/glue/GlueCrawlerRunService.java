package io.github.hectorvent.floci.services.glue;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.glue.model.Crawler;
import io.github.hectorvent.floci.services.glue.model.CrawlerRunRecord;
import io.github.hectorvent.floci.services.glue.model.LastCrawlInfo;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Glue crawler runs. No data store is crawled and no table is written: a crawl follows the crawler
 * state machine (READY, RUNNING, back to READY with a LastCrawl status) and settles lazily when
 * read. With the default {@code crawler-run-duration-seconds} of 0 a crawl finishes as soon as it
 * starts; a positive duration keeps the crawler RUNNING for that long.
 *
 * <p>Every public method is synchronized. Starting and stopping a crawl, and the crawler mutations
 * AWS refuses while a crawl runs (UpdateCrawler, DeleteCrawler), check the crawl state and act on
 * it; the store has no atomic compare and set, so those steps must not interleave.
 */
@ApplicationScoped
public class GlueCrawlerRunService {

    private static final Logger LOG = Logger.getLogger(GlueCrawlerRunService.class);

    static final String STATE_READY = "READY";
    static final String STATE_RUNNING = "RUNNING";
    static final String STATUS_SUCCEEDED = "SUCCEEDED";
    static final String STATUS_CANCELLED = "CANCELLED";

    private static final String LOG_GROUP = "/aws-glue/crawlers";
    // Enough history for a stable median without letting a long-lived crawler grow without bound.
    private static final int MAX_RUNTIME_HISTORY = 100;

    private final StorageBackend<String, CrawlerRunRecord> recordStore;
    private final GlueService glueService;
    private final int runDurationSeconds;
    private final Clock clock;

    @Inject
    public GlueCrawlerRunService(StorageFactory storageFactory, GlueService glueService, EmulatorConfig config) {
        this(storageFactory.create("glue", "crawler_runs.json", new TypeReference<>() {}),
                glueService, config.services().glue().crawlerRunDurationSeconds(), Clock.systemUTC());
    }

    GlueCrawlerRunService(StorageBackend<String, CrawlerRunRecord> recordStore, GlueService glueService,
                          int runDurationSeconds, Clock clock) {
        if (runDurationSeconds < 0) {
            throw new IllegalArgumentException(
                    "floci.services.glue.crawler-run-duration-seconds must not be negative: " + runDurationSeconds);
        }
        this.recordStore = recordStore;
        this.glueService = glueService;
        this.runDurationSeconds = runDurationSeconds;
        this.clock = clock;
    }

    public synchronized void startCrawler(String name) {
        glueService.getCrawler(name);
        CrawlerRunRecord record = settledRecord(name);
        if (record.getCurrentStart() != null) {
            throw new AwsException("CrawlerRunningException", "Crawler with name " + name + " has already started", 400);
        }
        record.setCurrentStart(clock.instant());
        record.setCurrentMessagePrefix(UUID.randomUUID().toString());
        recordStore.put(name, record);
        LOG.infov("Started Glue crawler {0}", name);
        settle(record);
    }

    public synchronized void stopCrawler(String name) {
        glueService.getCrawler(name);
        CrawlerRunRecord record = settledRecord(name);
        if (record.getCurrentStart() == null) {
            throw new AwsException("CrawlerNotRunningException", "Crawler with name " + name + " isn't running", 400);
        }
        finish(record, clock.instant(), STATUS_CANCELLED);
        LOG.infov("Stopped Glue crawler {0}", name);
    }

    /** Fills in the crawl state of a crawler read from the store: State, CrawlElapsedTime, LastCrawl. */
    public synchronized Crawler withRunState(Crawler crawler) {
        CrawlerRunRecord record = settledRecord(crawler.getName());
        Instant now = clock.instant();
        if (record.getCurrentStart() != null) {
            crawler.setState(STATE_RUNNING);
            crawler.setCrawlElapsedTime(Duration.between(record.getCurrentStart(), now).toMillis());
        } else {
            crawler.setState(STATE_READY);
            crawler.setCrawlElapsedTime(null);
        }
        if (record.getLastStatus() != null) {
            LastCrawlInfo lastCrawl = new LastCrawlInfo();
            lastCrawl.setStatus(record.getLastStatus());
            lastCrawl.setStartTime(record.getLastStart());
            lastCrawl.setLogGroup(LOG_GROUP);
            lastCrawl.setLogStream(crawler.getName());
            lastCrawl.setMessagePrefix(record.getLastMessagePrefix());
            crawler.setLastCrawl(lastCrawl);
        } else {
            crawler.setLastCrawl(null);
        }
        return crawler;
    }

    public synchronized List<Crawler> withRunState(List<Crawler> crawlers) {
        for (Crawler crawler : crawlers) {
            withRunState(crawler);
        }
        return crawlers;
    }

    /**
     * Metrics for the named crawlers, or for every crawler when no names are given. A name that
     * matches no crawler is skipped: the operation declares no EntityNotFoundException.
     */
    public synchronized GlueService.Page<Map<String, Object>> getCrawlerMetrics(List<String> names,
                                                                              Integer maxResults,
                                                                              String nextToken) {
        List<String> selected = new ArrayList<>();
        if (names == null || names.isEmpty()) {
            for (Crawler crawler : glueService.getCrawlers()) {
                selected.add(crawler.getName());
            }
        } else {
            for (Crawler crawler : glueService.batchGetCrawlers(names).crawlers()) {
                selected.add(crawler.getName());
            }
        }
        selected.sort(Comparator.naturalOrder());
        List<Map<String, Object>> metrics = new ArrayList<>();
        for (String name : selected) {
            metrics.add(metricsFor(settledRecord(name)));
        }
        return glueService.paginate(metrics, maxResults, nextToken);
    }

    public synchronized void updateCrawler(Crawler update) {
        requireNotRunning(update.getName());
        glueService.updateCrawler(update);
    }

    /** Crawl records belong to their crawler: deleting it removes them, and a running crawler cannot be deleted. */
    public synchronized void deleteCrawler(String name, String region) {
        requireNotRunning(name);
        glueService.deleteCrawler(name, region);
        recordStore.delete(name);
    }

    public synchronized void updateCrawlerSchedule(String name, String expression) {
        glueService.updateCrawlerSchedule(name, expression);
    }

    public synchronized void startCrawlerSchedule(String name) {
        glueService.startCrawlerSchedule(name);
    }

    public synchronized void stopCrawlerSchedule(String name) {
        glueService.stopCrawlerSchedule(name);
    }

    private void requireNotRunning(String name) {
        if (name != null && settledRecord(name).getCurrentStart() != null) {
            throw new AwsException("CrawlerRunningException", "Crawler with name " + name + " is running", 400);
        }
    }

    private Map<String, Object> metricsFor(CrawlerRunRecord record) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("CrawlerName", record.getCrawlerName());
        double timeLeft = 0;
        if (record.getCurrentStart() != null) {
            Instant finishesAt = record.getCurrentStart().plusSeconds(runDurationSeconds);
            timeLeft = Math.max(0, Duration.between(clock.instant(), finishesAt).toMillis() / 1000.0);
        }
        metrics.put("TimeLeftSeconds", timeLeft);
        metrics.put("StillEstimating", false);
        List<Double> runtimes = record.getRuntimeSeconds();
        metrics.put("LastRuntimeSeconds", runtimes.isEmpty() ? 0.0 : runtimes.getLast());
        metrics.put("MedianRuntimeSeconds", median(runtimes));
        metrics.put("TablesCreated", 0);
        metrics.put("TablesUpdated", 0);
        metrics.put("TablesDeleted", 0);
        return metrics;
    }

    private static double median(List<Double> values) {
        if (values.isEmpty()) {
            return 0.0;
        }
        List<Double> sorted = new ArrayList<>(values);
        sorted.sort(Comparator.naturalOrder());
        int middle = sorted.size() / 2;
        return sorted.size() % 2 == 1 ? sorted.get(middle) : (sorted.get(middle - 1) + sorted.get(middle)) / 2.0;
    }

    private CrawlerRunRecord settledRecord(String name) {
        CrawlerRunRecord record = recordStore.get(name).orElseGet(() -> {
            CrawlerRunRecord fresh = new CrawlerRunRecord();
            fresh.setCrawlerName(name);
            return fresh;
        });
        settle(record);
        return record;
    }

    private void settle(CrawlerRunRecord record) {
        if (record.getCurrentStart() == null) {
            return;
        }
        Instant finishesAt = record.getCurrentStart().plusSeconds(runDurationSeconds);
        if (!clock.instant().isBefore(finishesAt)) {
            finish(record, finishesAt, STATUS_SUCCEEDED);
        }
    }

    private void finish(CrawlerRunRecord record, Instant finishedAt, String status) {
        List<Double> runtimes = new ArrayList<>(record.getRuntimeSeconds());
        runtimes.add(Duration.between(record.getCurrentStart(), finishedAt).toMillis() / 1000.0);
        if (runtimes.size() > MAX_RUNTIME_HISTORY) {
            runtimes.removeFirst();
        }
        record.setRuntimeSeconds(runtimes);
        record.setLastStart(record.getCurrentStart());
        record.setLastStatus(status);
        record.setLastMessagePrefix(record.getCurrentMessagePrefix());
        record.setCurrentStart(null);
        record.setCurrentMessagePrefix(null);
        recordStore.put(record.getCrawlerName(), record);
    }
}
