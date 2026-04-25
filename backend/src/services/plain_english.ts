import Anthropic from "@anthropic-ai/sdk";
import { config } from "../config";
import { logger } from "../utils/logger";

export type TranslationLevel = "nerd" | "standard" | "grandma";

export type DeviceContext = {
    hostname?: string;
    vendor?: string;
    ip_address?: string;
    risk_score?: number;
    status?: string;
    first_seen?: string;
    recent_anomaly_count?: number;
    recent_ids_signal_count?: number;
};

let _client: Anthropic | null = null;

function getClient(): Anthropic | null {
    if (!config.ANTHROPIC_API_KEY) return null;
    if (!_client) {
        _client = new Anthropic({ apiKey: config.ANTHROPIC_API_KEY });
    }
    return _client;
}

// ── Daily call budget ──
let _budgetDay = "";
let _budgetCount = 0;

function withinDailyBudget(): boolean {
    if (config.AI_DAILY_CALL_LIMIT === 0) return false;
    const today = new Date().toISOString().slice(0, 10);
    if (today !== _budgetDay) {
        _budgetDay = today;
        _budgetCount = 0;
    }
    if (_budgetCount >= config.AI_DAILY_CALL_LIMIT) {
        logger.warn(
            `AI daily call limit (${config.AI_DAILY_CALL_LIMIT}) reached — falling back to static explanation`,
        );
        return false;
    }
    _budgetCount++;
    return true;
}

// ── Static fallbacks (used when AI is unavailable) ──

function staticExplanation(type: string, data: any, level: TranslationLevel): string {
    switch (type) {
        case "dns_block":
            if (level === "nerd")
                return `DNS resolution for ${data?.domain || "a domain"} was blocked by the sinkhole — the query matched the threat blocklist.`;
            if (level === "grandma")
                return "One of your devices tried to visit a dangerous website, and Bastión blocked it before anything could happen.";
            return "A device on your network attempted to access a blocked or suspicious domain.";

        case "traffic_spike":
            if (level === "nerd")
                return `Outbound byte volume exceeded the baseline by a statistically significant margin (high z-score). Possible data exfiltration or misconfigured service.`;
            if (level === "grandma")
                return "One of your devices sent a lot more data than usual. It's worth checking what it was doing.";
            return "A device generated unusually high network activity compared to its normal behavior.";

        case "anomaly":
            if (level === "nerd")
                return `Behavioral anomaly detected — device metrics deviated beyond threshold from established baseline. Review flow summary for signal details.`;
            if (level === "grandma")
                return "One of your devices started acting differently than it normally does. Bastión flagged it just in case.";
            return "The system detected unusual network behavior from a device.";

        case "ids_alert":
            if (level === "nerd")
                return `Suricata IDS fired on this traffic${data?.signature ? ` — rule: "${data.signature}"` : ""}. Check EVE log for full packet context.`;
            if (level === "grandma")
                return "Bastión's security scanner recognized a known dangerous pattern in your network traffic and flagged it.";
            return `The gateway IDS flagged this traffic as suspicious${data?.signature ? ` (${data.signature})` : ""}.`;

        case "correlated_threat":
            if (level === "nerd")
                return `Multiple independent signals (anomaly + IDS/DNS) converged on this device within the correlation window, raising confidence above threshold.`;
            if (level === "grandma")
                return "Several warning signs all pointed at the same device at the same time. That's a stronger sign something might be wrong.";
            return "Multiple signals agree that this device is behaving suspiciously, increasing confidence that the activity is real.";

        case "enforcement.monitor_only":
            if (level === "nerd")
                return "Enforcement threshold crossed but gateway is in monitor-only mode — nftables rule was not applied. No traffic was blocked.";
            if (level === "grandma")
                return "Bastión would have blocked this device, but it's set to watch-only mode right now, so it just took note instead.";
            return "The device crossed the enforcement threshold, but the gateway is in monitor-only mode so no block was applied.";

        default:
            if (level === "nerd")
                return `Unclassified security event (type: ${type}). Review raw event data for details.`;
            if (level === "grandma")
                return "Bastión noticed something unusual on your network.";
            return "Suspicious network activity was detected.";
    }
}

// ── AI prompt builder ──

const _audienceMap: Record<TranslationLevel, string> = {
    nerd: "a network security engineer — include technical detail: protocols, attack vectors, signal specifics, and what to investigate next.",
    standard: "a small business owner with basic tech awareness — plain English, no heavy jargon, explain why it matters.",
    grandma: "someone with zero technical knowledge — use simple everyday analogies, no acronyms, reassure while being clear about the risk.",
};

function buildPrompt(
    type: string,
    data: any,
    level: TranslationLevel,
    deviceContext?: DeviceContext
): string {
    const audience = _audienceMap[level];
    const deviceInfo = deviceContext
        ? `Device: ${deviceContext.hostname || "unknown"} (${deviceContext.vendor || "unknown vendor"}, ${deviceContext.ip_address || "unknown IP"}), risk score: ${deviceContext.risk_score ?? "?"}, status: ${deviceContext.status || "unknown"}.${deviceContext.recent_anomaly_count !== undefined ? ` Recent anomalies: ${deviceContext.recent_anomaly_count}.` : ""}${deviceContext.recent_ids_signal_count !== undefined ? ` Recent IDS signals: ${deviceContext.recent_ids_signal_count}.` : ""}`
        : "";

    return (
        `You are a network security assistant for Bastión Xólot, a home and small-business security gateway. ` +
        `Write 1-2 sentences explaining this alert to ${audience} ` +
        `Be specific about what happened and why it matters. No bullet points. No markdown headers.\n\n` +
        `Alert type: ${type}\n` +
        `Evidence: ${JSON.stringify(data)}\n` +
        (deviceInfo ? `${deviceInfo}\n` : "")
    );
}

// ── AI call ──

async function callAI(
    type: string,
    data: any,
    level: TranslationLevel,
    deviceContext: DeviceContext | undefined,
    client: Anthropic
): Promise<string | null> {
    try {
        const message = await client.messages.create({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 150,
            messages: [
                {
                    role: "user",
                    content: buildPrompt(type, data, level, deviceContext),
                },
            ],
        });

        const block = message.content[0];
        if (block.type === "text") {
            return block.text.replace(/^#+\s.*\n?/gm, "").trim();
        }
        return null;
    } catch (err) {
        logger.warn("AI explanation generation failed", { error: String(err) });
        return null;
    }
}

/**
 * Returns a plain-English explanation of a security event.
 *
 * Tries the Claude API first (level-aware prompt). Falls back to static
 * strings if the API key is missing, the daily budget is exhausted, or
 * the call fails.
 */
export async function explainSecurityEvent(
    type: string,
    data: any,
    level: TranslationLevel = "standard",
    deviceContext?: DeviceContext
): Promise<string> {
    const client = getClient();
    if (client && withinDailyBudget()) {
        const ai = await callAI(type, data, level, deviceContext, client);
        if (ai) return ai;
    }
    return staticExplanation(type, data, level);
}
