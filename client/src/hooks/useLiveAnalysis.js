// useLiveAnalysis.js
// ─────────────────────────────────────────────────────────────
// Custom React hook that manages the scam analysis workflow.
//
// WHY A CUSTOM HOOK?
// Without this hook, every component that needs to trigger
// analysis would duplicate: loading state, error state, API calls,
// and debounce logic. A custom hook packages all of that into
// one reusable unit. Components just call useAnalysis() and get
// back everything they need.
//
// WHAT THIS HOOK PROVIDES:
//   result    → the analysis data from the backend (or null)
//   loading   → true while the API call is in flight
//   error     → error message string (or null)
//   analyze   → function to call with input string
//   reset     → clears all state back to initial
// ─────────────────────────────────────────────────────────────

import { useState, useCallback, useRef } from "react";
import { analyzeInput } from "../services/api";
import debounce from "../utils/debounce";

const useLiveAnalysis = () => {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // useRef stores the debounced function without causing re-renders.
  // We use useRef instead of useMemo here because the debounced
  // function itself shouldn't change between renders.
  const debouncedAnalyze = useRef(
    debounce(async (input) => {
      // Don't analyze very short inputs — not enough signal
      if (!input || input.trim().length < 5) {
        setResult(null);
        setLoading(false);
        return;
      }

      try {
        setError(null);
        const data = await analyzeInput(input.trim());
        setResult(data);
      } catch (err) {
        // Show the server's error message if available, else a generic one
        const message =
          err.response?.data?.error ||
          "Analysis failed. Please check your connection and try again.";
        setError(message);
        setResult(null);
      } finally {
        setLoading(false);
      }
    }, 700) // 700ms debounce: fires 700ms after the user stops typing
  ).current;

  /**
   * Call this when the user types or submits input.
   * Sets loading immediately so the UI can show a spinner right away,
   * then the debounced function fires after 700ms of no new calls.
   */
  const analyze = useCallback(
    (input) => {
      if (!input || input.trim().length < 5) {
        setResult(null);
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      debouncedAnalyze(input);
    },
    [debouncedAnalyze]
  );

  /**
   * Resets all state — called when user clears the input
   * or navigates back to the home screen.
   */
  const reset = useCallback(() => {
    setResult(null);
    setLoading(false);
    setError(null);
  }, []);

  return { result, loading, error, analyze, reset };
};

export default useLiveAnalysis;
