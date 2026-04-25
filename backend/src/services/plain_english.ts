import Anthropic from "@anthropic-ai/sdk";
import { config } from "../config";
import { logger } from "../utils/logger";

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

/**
 * Converts technical security data into human-readable explanation.
 * Used as a synchronous fallback when AI is unavailable.
 */
export function explainSecurityEvent(type: string, data: any): string {
    switch (type) {
        case "dns_block":
            return "A device on your network attempted to access a blocked or suspicious domain.";
        case "traffic_spike":
            return "A device generated unusually high network activity compared to its normal behavior.";
        case "anomaly":
            return "The system detected unusual network behavior from a device.";
        case "ids_alert":
            return `The gateway IDS flagged this traffic as suspicious${data?.signature ? ` (${data.signature})` : ""}.`;
        case "correlated_threat":
            return "Multiple signals agree that this device is behaving suspiciously, increasing confidence that the activity is real.";
        case "enforcement.monitor_only":
            return "The device crossed the enforcement threshold, but the gateway is in monitor-only mode so no block was applied.";
        default:
            return "Suspicious network activity was detected.";
    }
}

/**
 * Calls the Claude API to generate a plain-English alert explanation.
 *
 * Returns null if ANTHROPIC_API_KEY is not configured or the call fails.
 * The caller should fall back to explainSecurityEvent() in that case.
 */
export async function generateAIExplanation(
    alertType: string,
    severity: string,
    title: string,
    evidence: Record<string, unknown>
): Promise<string | null> {
    const client = getClient();
    if (!client) return null;
    if (!withinDailyBudget()) return null;

    try {
        const message = await client.messages.create({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 120,
            messages: [
                {
                    role: "user",
                    content:
                        `You are a home network security assistant. Write 1-2 sentences explaining this alert to a non-technical homeowner. Be specific about what happened and why it matters. No jargon, no bullet points.\n\n` +
                        `Alert type: ${alertType}\n` +
                        `Severity: ${severity}\n` +
                        `Title: ${title}\n` +
                        `Evidence: ${JSON.stringify(evidence)}`,
                },
            ],
        });

        const block = message.content[0];
        if (block.type === "text") {
            return block.text
                .replace(/^#+\s.*\n?/gm, "")
                .trim();
        }
        return null;
    } catch (err) {
        logger.warn("AI explanation generation failed", { error: String(err) });
        return null;
    }
}
