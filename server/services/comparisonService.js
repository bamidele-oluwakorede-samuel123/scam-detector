// comparisonService.js
// Formats the "Legitimate vs Scam" comparison data that OPEN_ROUTER AI
// generates, and provides fallbacks when AI data is unavailable.

/**
 * Builds a structured comparison object for the frontend.
 *
 * @param {object} aiComparison - { legitimate: string, scam: string } from OPEN_ROUTER AI
 * @param {string} inputType - "url" | "phone" | "email" | "text"
 * @returns {{ legitimate: string, scam: string }}
 */
const buildComparison = (aiComparison, inputType) => {
  // If the AI gave a proper comparison, i make use of it
  if (
    aiComparison &&
    aiComparison.legitimate &&
    aiComparison.scam &&
    aiComparison.legitimate !== "Unable to generate comparison."
  ) {
    return {
      legitimate: aiComparison.legitimate,
      scam: aiComparison.scam,
    };
  }

  // ── Fallback comparisons by input type -----
  // It is used when the AI fails or returns empty comparison data.
  const fallbacks = {
    url: {
      legitimate: "Legitimate sites use your bank's exact domain (e.g., chase.com), always show HTTPS, and never ask you to click a shortened link to verify your account.",
      scam: "Scam URLs often include a brand name with extra words (e.g., chase-secure-verify.com), may use HTTP, and lead to fake login pages designed to steal your password.",
    },
    phone: {
      legitimate: "Legitimate companies call from numbers listed on their official website and never ask you to call premium-rate numbers or share OTP codes over the phone.",
      scam: "Scam callers often use spoofed numbers, pressure you to act immediately, and ask for PINs, passwords, or gift card payments.",
    },
    email: {
      legitimate: "Legitimate emails come from the company's actual domain (e.g., support@paypal.com), address you by name, and never ask for your password via email.",
      scam: "Scam emails use misspelled domains (e.g., paypa1.com), create urgency, and link to fake sites that steal your credentials.",
    },
    text: {
      legitimate: "Legitimate messages from organizations contain your name, reference a real account or transaction, and provide ways to verify through official channels.",
      scam: "Scam messages are often generic, create urgency, contain suspicious links, and ask you to act before you can think it through.",
    },
  };

  return fallbacks[inputType] || fallbacks.text;
};

export default buildComparison;
