// aiService.js
// Handles all communication with the AI via OpenRouter.


import aiConfig from "../config/aiConfig.js";

// ── System Prompt -----
// The system prompt defines the AI's role and EXACT output format.
// This is the first message sent to any model through OpenRouter.
const SYSTEM_PROMPT = `You are an expert cybersecurity analyst specializing in scam detection.
Your job is to analyze user-submitted content (URLs, phone numbers, emails, or text messages)
and determine whether it is a scam, phishing attempt, or legitimate communication.

You MUST respond with ONLY a valid JSON object — no explanation, no markdown, no preamble, no backticks.

The JSON must have exactly this structure:
{
  "riskScore": <number 0-100>,
  "verdict": "<one sentence summary of your conclusion>",
  "explanation": "<2-4 sentences explaining why this is or isn't a scam, written for a general audience with no technical background>",
  "additionalFlags": ["<flag1>", "<flag2>"],
  "comparison": {
    "legitimate": "<what a legitimate version of this would look like>",
    "scam": "<what makes this version suspicious or how scammers typically present this>"
  }
}

Scoring guidelines:
- riskScore 0-30: Safe / legitimate
- riskScore 31-60: Suspicious, use with caution
- riskScore 61-100: Very likely a scam

Writing guidelines:
- Write the explanation for someone with no technical background
- Be specific — mention actual details from the input, not generic warnings
- additionalFlags should only contain NEW flags not already listed in the pre-detected flags`;

/**
 * Sends the user's input to OpenRouter and returns a structured analysis.
 *
 * @param {string} input - The user's raw input (URL, phone, email, or text)
 * @param {string} inputType - "url" | "phone" | "email" | "text"
 * @param {string[]} preDetectedFlags - Flags already found by pattern detection
 * @returns {Promise<{
 *   riskScore: number,
 *   verdict: string,
 *   explanation: string,
 *   additionalFlags: string[],
 *   comparison: { legitimate: string, scam: string }
 * }>}
 */
const analyzeWithAI = async (input, inputType, preDetectedFlags = []) => {
  // ── Build the user message -----
  // Giving the AI the input, the type, and the flags already
  // found — so it can focus on adding context, not repeating work.
  const userMessage = `
Analyze the following ${inputType} for scam indicators:

INPUT:
${input}

PRE-DETECTED PATTERN FLAGS (already found by automated rules — do NOT repeat these):
${preDetectedFlags.length > 0 ? preDetectedFlags.map((f) => `- ${f}`).join("\n") : "None detected by automated rules"}

Respond ONLY with a valid JSON object. No markdown, no backticks, no extra text.
  `.trim();

  // ── Call OpenRouter API -----
  // OpenRouter's endpoint follows the OpenAI chat completions format.
  // Required headers:
  //   Authorization: Bearer <my-api-key>  ← authenticates your request
  //   Content-Type: application/json         ← tells the server we're sending JSON
  //   HTTP-Referer: <your-site>              ← OpenRouter asks for this (can be anything)
  //   X-Title: <app-name>                   ← shown in your OpenRouter dashboard logs
  const response = await fetch(aiConfig.openRouterBaseUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${aiConfig.openRouterApiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "http://localhost:3000",   // Your app's URL (update for production)
      "X-Title": "ScamShield Detector",          // Appears in your OpenRouter usage logs
    },
    body: JSON.stringify({
      // Which model to use
      model: aiConfig.model,

      // max_tokens limits how long the AI's response can be.
      max_tokens: aiConfig.maxTokens,

      // The messages array is how OpenAI-format APIs work:
      // - "system" role: instructions and persona for the AI
      // - "user" role: the actual input/question
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: userMessage  },
      ],
    }),
  });

  // ── Check for HTTP errors -------
  // A non-OK status (e.g., 401 = bad API key, 429 = rate limit)
  // means the request failed before the AI even ran.
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`OpenRouter API error ${response.status}: ${errorBody}`);
  }

  // ── Extract the AI's text --------
  // OpenRouter returns JSON in this shape:
  // {
  //   choices: [
  //     { message: { role: "assistant", content: "<the AI's reply>" } }
  //   ]
  // }
  // grab choices[0].message.content — that's the AI's full text output.
  const data = await response.json();
  const rawText = data.choices?.[0]?.message?.content || "";

  // ── Clean and parse the JSON -----
  // Some models wrap their JSON in markdown code fences like ```json ... ```
  // even when told not to. We strip those just in case.
  const cleanJSON = rawText
    .replace(/```json/gi, "") // Remove opening ```json
    .replace(/```/g, "")      // Remove closing ```
    .trim();

  // ──  Parse with fallback ----
  let parsed;
  try {
    parsed = JSON.parse(cleanJSON);
  } catch (err) {
    // If the model returned something that can't parse as JSON,
    // log it for debugging and return a safe fallback result.
    // The pattern-based detection results will still be shown.
    console.error("AI JSON parse error:", err.message);
    console.error("Raw AI output was:", rawText);
    parsed = {
      riskScore: 50,
      verdict: "Analysis inconclusive — please review manually.",
      explanation:
        "The AI analysis encountered a formatting issue. " +
        "Pattern-based detection results are still shown above.",
      additionalFlags: [],
      comparison: {
        legitimate: "Unable to generate comparison at this time.",
        scam: "Unable to generate comparison at this time.",
      },
    };
  }

  return parsed;
};

export default analyzeWithAI;
