package org.jetbrains.nativecerts;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import java.util.logging.Logger;

public class NativeCertsSetupLoggingRuleTest {
    @Rule
    public final NativeCertsSetupLoggingRule loggingRule = new NativeCertsSetupLoggingRule();

    @Test
    public void smoke() {
        Logger logger = Logger.getLogger(NativeCertsSetupLoggingRuleTest.class.getName());
        logger.warning("WARNING");
        logger.severe("ERROR");
        Assert.assertEquals(2, loggingRule.numberOfWarningsOrAbove());
    }
}
