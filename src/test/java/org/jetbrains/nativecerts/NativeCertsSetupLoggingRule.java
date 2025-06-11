package org.jetbrains.nativecerts;

import org.junit.rules.ExternalResource;

public class NativeCertsSetupLoggingRule extends ExternalResource {
    @Override
    protected void before() {
        NativeCertsTestLogHandler.reset();
    }

    @Override
    protected void after() {
        if (NativeCertsTestLogHandler.numberOfWarningsOrAbove() > 0) {
            throw new AssertionError("There were " + NativeCertsTestLogHandler.numberOfWarningsOrAbove() + " warnings or above");
        }
    }
}
