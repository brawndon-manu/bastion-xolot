type LogLevel = "info" | "warn" | "error" | "debug";

type LogContext = Record<string, unknown> | undefined;

/**
 * Writes a structured log line as JSON.
 * 
 * Using a single helper keeps log formatting consistent across the backend,
 * which makes it easier to grep logs locally or parse them later if needed.
 */
function write(level: LogLevel, message: string, context?: LogContext) {
    const entry = {
        level,
        time: new Date().toISOString(),
        message,
        ...(context ? { context } : {}),
    };

    const line = JSON.stringify(entry);

    /**
     * Route warnings and errors to their matching console methods so they are
     * easier to spot in terminal output and external logging systems.
     */
    if (level === "error") {
        console.error(line);
        return;
    }

    if (level === "warn") {
        console.warn(line);
        return;
    }

    console.log(line);
}

/**
 * Lightweight structured logger used by the backend.
 * 
 * The interface stays intentionally small:
 *  - info  -> normal lifecycle messages
 *  - warn  -> unexpected but recoverable conditions
 *  - error -> failures that need attention
 *  - debug -> extra local-development detail
 */
export const logger = {
    info(message: string, context?: LogContext) {
        write("info", message, context);
    },

    warn(message: string, context?: LogContext) {
        write("warn", message, context);
    },

    error(message: string, context?: LogContext) {
        write("error", message, context);
    },

    /**
     * Debug logging is disabled in production so routine verbose output does not
     * clutter appliance logs during demos or deployment.
     */
    debug(message: string, context?: LogContext) {
        if (process.env.NODE_ENV !== "production") {
            write("debug", message, context);
        }
    },
};
