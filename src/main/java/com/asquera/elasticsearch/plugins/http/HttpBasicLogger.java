package com.asquera.elasticsearch.plugins.http;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.ESLoggerFactory;

public class HttpBasicLogger {
    private static ESLogger esLogger;

    static {
        esLogger = ESLoggerFactory.getLogger("HttpBasicLogger");
    }

    public static void debug(String msg, Object... var2) {
        esLogger.debug(msg, var2);
    }

    public static void info(String msg, Object... var2) {
        esLogger.info(msg, var2);
    }

    public static void warn(String msg, Object... var2) {
        esLogger.warn(msg, var2);
    }

    public static void error(String msg, Object... var2) {
        esLogger.error(msg, var2);
    }

    public static void error(String msg, Exception exp, Object... var3) {
        esLogger.error(msg, exp, var3);
    }
}
