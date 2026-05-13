// aiService.js
// ─────────────────────────────────────────────────────────────
// Handles all communication with the AI via OpenRouter.
//
// WHAT IS OPENROUTER?
// OpenRouter (https://openrouter.ai) is a service that routes
// your API requests to hundreds of different AI models — including
// many free ones — using a single API key and a single endpoint.
// It uses the OpenAI chat format, which is the industry standard.
//
// HOW THE OPENAI CHAT FORMAT WORKS:
// Instead of a separate "system" parameter (like Anthropic uses),
// OpenRouter/OpenAI puts the system instruction as the FIRST message
// in the messages array with role: "system". Then the user's input
// goes as role: "user". The AI responds as role: "assistant".
//
// KEY DESIGN DECISIONS:
// 1. We use fetch() directly — no SDK needed. OpenRouter's API
//    is a simple HTTP POST with JSON body and Bearer auth header.
// 2. We ask the AI to respond ONLY in JSON — structured output
//    makes parsing reliable regardless of which model you pick.
// 3. We pass pre-detected pattern flags so the AI focuses on
//    context and nuance rather than re-detecting obvious things.
// ─────────────────────────────────────────────────────────────

import aiConfig from "../config/aiConfig.js";

// ── System Prompt ─────────────────────────────────────────────
// The system prompt defines the AI's role and EXACT output format.
// This is the first message sent to any model through OpenRouter.
// A well-written system prompt = consistent, parseable output
// regardless of which underlying model you choose.
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
 * HOW THIS FUNCTION WORKS STEP BY STEP:
 * 1. Build the messages array: [systemMessage, userMessage]
 * 2. POST to OpenRouter's endpoint with our API key in the header
 * 3. Extract the AI's text response from the response JSON
 * 4. Strip any accidental markdown formatting (```json blocks)
 * 5. Parse the JSON and return it
 * 6. If parsing fails, return a safe fallback object
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
  // ── Step 1: Build the user message ───────────────────────────
  // We give the AI the input, the type, and the flags we already
  // found — so it can focus on adding context, not repeating work.
  const userMessage = `
Analyze the following ${inputType} for scam indicators:

INPUT:
${input}

PRE-DETECTED PATTERN FLAGS (already found by automated rules — do NOT repeat these):
${preDetectedFlags.length > 0 ? preDetectedFlags.map((f) => `- ${f}`).join("\n") : "None detected by automated rules"}

Respond ONLY with a valid JSON object. No markdown, no backticks, no extra text.
  `.trim();

  // ── Step 2: Call OpenRouter API ───────────────────────────────
  // OpenRouter's endpoint follows the OpenAI chat completions format.
  // Required headers:
  //   Authorization: Bearer <your-api-key>  ← authenticates your request
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
      // Which model to use — set this in .env as OPENROUTER_MODEL
      model: aiConfig.model,

      // max_tokens limits how long the AI's response can be.
      // 1024 is plenty for our JSON structure.
      max_tokens: aiConfig.maxTokens,

      // The messages array is how OpenAI-format APIs work:
      // - "system" role: instructions and persona for the AI
      // - "user" role: the actual input/question
      // - "assistant" role: would be used if we were doing multi-turn chat
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user",   content: userMessage  },
      ],
    }),
  });

  // ── Step 3: Check for HTTP errors ────────────────────────────
  // A non-OK status (e.g., 401 = bad API key, 429 = rate limit)
  // means the request failed before the AI even ran.
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`OpenRouter API error ${response.status}: ${errorBody}`);
  }

  // ── Step 4: Extract the AI's text ────────────────────────────
  // OpenRouter returns JSON in this shape:
  // {
  //   choices: [
  //     { message: { role: "assistant", content: "<the AI's reply>" } }
  //   ]
  // }
  // We grab choices[0].message.content — that's the AI's full text output.
  const data = await response.json();
  const rawText = data.choices?.[0]?.message?.content || "";

  // ── Step 5: Clean and parse the JSON ─────────────────────────
  // Some models wrap their JSON in markdown code fences like ```json ... ```
  // even when told not to. We strip those just in case.
  const cleanJSON = rawText
    .replace(/```json/gi, "") // Remove opening ```json
    .replace(/```/g, "")      // Remove closing ```
    .trim();

  // ── Step 6: Parse with fallback ──────────────────────────────
  let parsed;
  try {
    parsed = JSON.parse(cleanJSON);
  } catch (err) {
    // If the model returned something we can't parse as JSON,
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

// ── Image System Prompt ───────────────────────────────────────
// Separate prompt for image analysis.
// We tell the AI to first READ what is in the image, then analyze
// it for scam indicators using the same JSON structure.
const IMAGE_SYSTEM_PROMPT = `You are an expert cybersecurity analyst specializing in scam detection.
The user will send you a screenshot or image that may contain a scam message, fake website,
phishing email, suspicious SMS, or fraudulent content.

Your job is to:
1. Read and extract all visible text from the image
2. Analyze the content for scam indicators
3. Return your findings as a structured JSON object

You MUST respond with ONLY a valid JSON object — no explanation, no markdown, no preamble, no backticks.

The JSON must have exactly this structure:
{
  "extractedText": "<all the text you can read from the image>",
  "riskScore": <number 0-100>,
  "verdict": "<one sentence summary of your conclusion>",
  "explanation": "<2-4 sentences explaining why this is or isn't a scam, written for a general audience>",
  "additionalFlags": ["<flag1>", "<flag2>"],
  "comparison": {
    "legitimate": "<what a legitimate version of this would look like>",
    "scam": "<what makes this version suspicious>"
  }
}

Scoring guidelines:
- riskScore 0-30: Safe / legitimate
- riskScore 31-60: Suspicious, use with caution
- riskScore 61-100: Very likely a scam

If the image is blurry or unreadable, set riskScore to 0 and explain in the verdict.`;

/**
 * Analyzes an image (screenshot) for scam indicators using a vision AI model.
 *
 * HOW IMAGE ANALYSIS WORKS WITH OPENROUTER:
 * Vision-capable models (like Gemini) accept images inside the message content
 * as a special object with type "image_url". The image is sent as a base64
 * data URL — meaning we encode the raw image bytes as a text string and send
 * it directly in the API request body. No file upload needed.
 *
 * Base64 data URL format:
 *   data:image/jpeg;base64,/9j/4AAQSkZJRgAB...
 *   └── mime type ──┘ └── base64 encoded image bytes ──┘
 *
 * @param {string} base64Image - Base64 encoded image string (without the data: prefix)
 * @param {string} mimeType - Image MIME type e.g. "image/jpeg", "image/png"
 * @returns {Promise<{
 *   extractedText: string,
 *   riskScore: number,
 *   verdict: string,
 *   explanation: string,
 *   additionalFlags: string[],
 *   comparison: { legitimate: string, scam: string }
 * }>}
 */
export const analyzeImageWithAI = async (base64Image, mimeType = "image/jpeg") => {
  // ── Step 1: Build the image data URL ─────────────────────────
  // OpenRouter vision models expect the image as a data URL.
  // Format: "data:<mimeType>;base64,<base64string>"
  const imageDataUrl = `data:${mimeType};base64,${base64Image}`;

  // ── Step 2: Build the message with image content ──────────────
  // Vision models accept content as an ARRAY of blocks instead of
  // a plain string. Each block is either:
  //   { type: "text", text: "..." }         ← text instruction
  //   { type: "image_url", image_url: {...} } ← the image itself
  const userContent = [
    {
      type: "text",
      text: "Analyze this image for scam indicators. Extract all visible text and determine if this is a scam. Respond ONLY with the JSON object specified in your instructions.",
    },
    {
      // The image block — this is what tells the AI to look at the image
      type: "image_url",
      image_url: {
        url: imageDataUrl, // The full base64 data URL
      },
    },
  ];

  // ── Step 3: Call OpenRouter API ───────────────────────────────
  // We use the vision model from aiConfig.
  // IMPORTANT: Make sure OPENROUTER_MODEL in your .env is set to a
  // vision-capable model like: google/gemini-2.0-flash-exp:free
  const response = await fetch(aiConfig.openRouterBaseUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${aiConfig.openRouterApiKey}`,
      "Content-Type": "application/json",
      "HTTP-Referer": "http://localhost:3000",
      "X-Title": "ScamShield Detector",
    },
    body: JSON.stringify({
      model: aiConfig.model,
      max_tokens: aiConfig.maxTokens,
      messages: [
        { role: "system", content: IMAGE_SYSTEM_PROMPT },
        { role: "user",   content: userContent },  // Array content for vision
      ],
    }),
  });

  // ── Step 4: Check for HTTP errors ────────────────────────────
  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`OpenRouter vision API error ${response.status}: ${errorBody}`);
  }

  // ── Step 5: Extract and parse the AI response ─────────────────
  const data = await response.json();
  const rawText = data.choices?.[0]?.message?.content || "";

  const cleanJSON = rawText
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();

  let parsed;
  try {
    parsed = JSON.parse(cleanJSON);
  } catch (err) {
    console.error("Image AI JSON parse error:", err.message);
    console.error("Raw output:", rawText);
    parsed = {
      extractedText: "Could not extract text from image.",
      riskScore: 50,
      verdict: "Image analysis inconclusive — please type the content manually.",
      explanation: "The AI could not fully process the image. Try uploading a clearer screenshot.",
      additionalFlags: [],
      comparison: {
        legitimate: "Unable to generate comparison.",
        scam: "Unable to generate comparison.",
      },
    };
  }

  return parsed;
};

export default analyzeWithAI;
