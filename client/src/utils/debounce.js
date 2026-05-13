// debounce.js
// ─────────────────────────────────────────────────────────────
// Debounce: delays execution of a function until the user has
// stopped calling it for `delay` milliseconds.
//
// EXAMPLE:
//   const debounced = debounce(analyzeText, 600);
//   // User types "hello" → debounced fires 600ms after they stop
//
// WHY WE NEED IT:
// Without debouncing, every keystroke would trigger an API call.
// With 600ms debounce, the API is only called when the user
// pauses — much more efficient.
// ─────────────────────────────────────────────────────────────

/**
 * @param {Function} func - The function to debounce
 * @param {number} delay - Milliseconds to wait after the last call
 * @returns {Function} Debounced version of func
 */
const debounce = (func, delay) => {
  let timeoutId;

  return (...args) => {
    // Cancel any pending call
    clearTimeout(timeoutId);

    // Schedule a new call after the delay
    timeoutId = setTimeout(() => {
      func(...args);
    }, delay);
  };
};

export default debounce;
