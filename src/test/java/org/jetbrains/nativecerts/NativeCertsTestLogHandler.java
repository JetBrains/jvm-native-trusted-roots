package org.jetbrains.nativecerts;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

public class NativeCertsTestLogHandler extends Handler {
    private static final AtomicInteger warningsOrAbove = new AtomicInteger();

    public static int numberOfWarningsOrAbove() {
        return warningsOrAbove.get();
    }

    public static void reset() {
        warningsOrAbove.set(0);
    }

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
}
