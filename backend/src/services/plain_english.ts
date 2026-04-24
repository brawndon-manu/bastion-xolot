/**
 * Translation layer between raw security events and user-facing explanations.
 *
 * Supports three verbosity levels driven by the user's chosen Translation View:
 *   "nerd"     — technical detail, protocol names, attack vectors
 *   "standard" — plain English, assumes basic network awareness
 *   "grandma"  — zero jargon, everyday analogies
 *
 * Used by:
 *  - correlation_service when creating alerts (defaults to "standard")
 *  - alerts route when the mobile app requests a specific level
 */

import Anthropic from "@anthropic-ai/sdk";

export type TranslationLevel = "nerd" | "standard" | "grandma";

export type DeviceContext = {
    hostname: string | null;
    vendor: string | null;
    ip_address: string | null;
    risk_score: number;
    status: string;
    first_seen: number;
    recent_anomaly_count?: number;
    recent_ids_signal_count?: number;
};

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const systemPrompts: Record<TranslationLevel, string> = {
    nerd: `You are a senior cybersecurity analyst reviewing a security event from a home network gateway. You will be given context about the specific device involved — use it to make your analysis concrete and personal to that device. Explain what happened with full technical detail — include protocol names, attack vectors, threat classifications, and relevant IOC context. Be precise and concise. One short paragraph.`,

    standard: `You are a helpful security assistant reviewing a security event from a home network gateway. You will be given context about the specific device involved — use it to make your explanation specific to that device rather than generic. Explain what happened for an everyday person who is not technical but is comfortable using technology. Use plain language, no jargon. Clearly say what the device did, whether it's a concern, and if they need to do anything. Be calm and direct. One short paragraph.`,

    grandma: `You are explaining a home network security event to someone with absolutely no technical background. You will be given context about the specific device involved — mention the device by name if you have it. Use simple everyday analogies. Be warm and reassuring while clearly stating whether they need to do anything. Keep it to 2-3 sentences max.`,
};

function buildUserMessage(type: string, data: any, ctx?: DeviceContext): string {
    const lines: string[] = [];

    if (ctx) {
        const identity = ctx.hostname || ctx.ip_address || "unknown device";
        const vendor = ctx.vendor || "unknown vendor";
        const onNetworkSince = new Date(ctx.first_seen).toISOString().split("T")[0];

        lines.push("Device context:");
        lines.push(`- Identity: ${identity} (${vendor})`);
        lines.push(`- IP: ${ctx.ip_address || "unknown"}`);
        lines.push(`- Risk score: ${ctx.risk_score}/100`);
        lines.push(`- Status: ${ctx.status}`);
        lines.push(`- On network since: ${onNetworkSince}`);
        if (ctx.recent_anomaly_count !== undefined) {
            lines.push(`- Recent behavioral anomalies (last 1h): ${ctx.recent_anomaly_count}`);
        }
        if (ctx.recent_ids_signal_count !== undefined) {
            lines.push(`- Recent IDS/suspicious signals (last 1h): ${ctx.recent_ids_signal_count}`);
        }
        lines.push("");
    }

    lines.push("Security event:");
    lines.push(`- Type: ${type}`);
    lines.push(`- Details: ${JSON.stringify(data, null, 2)}`);

    return lines.join("\n");
}

/**
 * Returns a human-readable AI-generated explanation for a security event at the given level.
 * Falls back to a generic message if the API call fails.
 */
export async function explainSecurityEvent(
    type: string,
    data: any,
    level: TranslationLevel = "standard",
    deviceContext?: DeviceContext
): Promise<string> {
    try {
        const message = await client.messages.create({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 300,
            system: systemPrompts[level],
            messages: [
                {
                    role: "user",
                    content: buildUserMessage(type, data, deviceContext),
                },
            ],
        });

        const block = message.content[0];
        return block.type === "text" ? block.text.trim() : "A security event was detected on your network.";
    } catch (err) {
        console.error("Failed to generate AI explanation:", err);
        return "A security event was detected on your network.";
    }
}
