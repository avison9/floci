package io.github.hectorvent.floci.services.glue.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Floci's own bookkeeping for a crawler's crawls; never sent on the wire. The crawl in progress (if
 * any), the last finished crawl, and the runtimes GetCrawlerMetrics summarises.
 */
@RegisterForReflection
public class CrawlerRunRecord {
    private String crawlerName;
    private Instant currentStart;
    private String currentMessagePrefix;
    private Instant lastStart;
    private String lastStatus;
    private String lastMessagePrefix;
    private List<Double> runtimeSeconds = new ArrayList<>();

    public CrawlerRunRecord() {}

    public String getCrawlerName() { return crawlerName; }
    public void setCrawlerName(String crawlerName) { this.crawlerName = crawlerName; }

    public Instant getCurrentStart() { return currentStart; }
    public void setCurrentStart(Instant currentStart) { this.currentStart = currentStart; }

    public String getCurrentMessagePrefix() { return currentMessagePrefix; }
    public void setCurrentMessagePrefix(String currentMessagePrefix) { this.currentMessagePrefix = currentMessagePrefix; }

    public Instant getLastStart() { return lastStart; }
    public void setLastStart(Instant lastStart) { this.lastStart = lastStart; }

    public String getLastStatus() { return lastStatus; }
    public void setLastStatus(String lastStatus) { this.lastStatus = lastStatus; }

    public String getLastMessagePrefix() { return lastMessagePrefix; }
    public void setLastMessagePrefix(String lastMessagePrefix) { this.lastMessagePrefix = lastMessagePrefix; }

    public List<Double> getRuntimeSeconds() { return runtimeSeconds; }
    public void setRuntimeSeconds(List<Double> runtimeSeconds) { this.runtimeSeconds = runtimeSeconds; }
}
