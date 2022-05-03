package org.jetbrains.nativecerts;

import org.junit.rules.ExternalResource;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.*;

public class NativeCertsSetupLoggingRule extends ExternalResource {
    private final ConsoleHandler consoleHandler = new ConsoleHandler();
    private final Handler countingHandler = new Handler() {
        @Override
        public void publish(LogRecord record) {
            if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                warningsOrAbove.incrementAndGet();
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() throws SecurityException {
        }
    };

    private Level oldRootLevel = null;
    private final AtomicInteger warningsOrAbove = new AtomicInteger();

    public NativeCertsSetupLoggingRule() {
        consoleHandler.setLevel(Level.FINEST);
        consoleHandler.setFormatter(new SimpleFormatter());
    }

    public int numberOfWarningsOrAbove() {
        return warningsOrAbove.get();
    }

    @Override
    protected void before() {
        Logger rootLogger = Logger.getLogger("");

        oldRootLevel = rootLogger.getLevel();
        rootLogger.setLevel(Level.FINE);

        rootLogger.addHandler(consoleHandler);
        rootLogger.addHandler(countingHandler);
    }

    @Override
    protected void after() {
        Logger rootLogger = Logger.getLogger("");
        rootLogger.removeHandler(countingHandler);
        rootLogger.removeHandler(consoleHandler);

        if (oldRootLevel != null) {
            rootLogger.setLevel(oldRootLevel);
            oldRootLevel = null;
        }
    }
}
