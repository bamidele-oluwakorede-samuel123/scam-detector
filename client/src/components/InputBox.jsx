// InputBox.jsx
// ─────────────────────────────────────────────────────────────
// The primary input component for the scam detector.
//
// FEATURES:
// - Auto-detects input type (URL / phone / email / text) as user types
// - Shows a type badge so the user knows what was detected
// - Triggers analysis via the analyze prop (from useLiveAnalysis)
// - Image upload button — converts image to Base64 and calls onAnalyzeImage
// - Submit button for deliberate submission
// - Clear button to reset
// ─────────────────────────────────────────────────────────────

import React, { useState, useEffect, useRef } from "react";

const detectType = (input) => {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (/^(https?:\/\/|www\.)|^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/|$)/i.test(trimmed)) return "url";
  if (/^\+?[\d\s\-\(\)]{7,20}$/.test(trimmed)) return "phone";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return "email";
  if (trimmed.length > 3) return "text";
  return null;
};

const TYPE_LABELS = {
  url:   { label: "URL / Link",       icon: "🔗" },
  phone: { label: "Phone Number",     icon: "📞" },
  email: { label: "Email Address",    icon: "✉️" },
  text:  { label: "Message / SMS",    icon: "💬" },
};

const InputBox = ({ onAnalyze, onAnalyzeImage, onClear, loading }) => {
  const [value, setValue] = useState("");
  const [detectedType, setDetectedType] = useState(null);
  const [imagePreview, setImagePreview] = useState(null); // Preview URL for selected image
  const [imageName, setImageName]       = useState("");
  const fileInputRef = useRef(null);     // Hidden file input reference

  useEffect(() => {
    setDetectedType(detectType(value));
  }, [value]);

  const handleChange = (e) => setValue(e.target.value);

  const handleSubmit = () => {
    if (value.trim().length >= 5) onAnalyze(value);
  };

  const handleClear = () => {
    setValue("");
    setDetectedType(null);
    setImagePreview(null);
    setImageName("");
    onClear();
  };

  const handleKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") handleSubmit();
  };

  // ── Image Upload Handler ──────────────────────────────────
  // When the user picks a file:
  // 1. Show a preview so they can see which image was selected
  // 2. Convert the file to Base64 using FileReader
  // 3. Call onAnalyzeImage with the Base64 string and mime type
  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file type
    const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif"];
    if (!allowed.includes(file.type)) {
      alert("Please upload a JPEG, PNG, WebP, or GIF image.");
      return;
    }

    // Validate file size (5MB max)
    if (file.size > 5 * 1024 * 1024) {
      alert("Image must be under 5MB.");
      return;
    }

    // Show preview
    setImagePreview(URL.createObjectURL(file));
    setImageName(file.name);

    // Convert file to Base64 using FileReader
    // FileReader is a built-in browser API — no libraries needed.
    // readAsDataURL() returns: "data:image/jpeg;base64,/9j/4AAQ..."
    // We split on the comma to get just the Base64 part (after the comma).
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl  = reader.result;              // Full data URL
      const base64   = dataUrl.split(",")[1];      // Just the Base64 string
      const mimeType = file.type;                  // e.g. "image/jpeg"
      onAnalyzeImage(base64, mimeType);            // Send to parent for API call
    };
    reader.readAsDataURL(file);
  };

  const typeInfo = detectedType ? TYPE_LABELS[detectedType] : null;

  return (
    <div style={styles.wrapper}>
      {/* Type detection badge */}
      <div style={styles.badgeRow}>
        {imagePreview ? (
          <span style={styles.badge}>
            <span style={styles.badgeIcon}>🖼️</span>
            Image selected: {imageName.length > 30 ? imageName.slice(0, 30) + "…" : imageName}
          </span>
        ) : typeInfo ? (
          <span style={styles.badge}>
            <span style={styles.badgeIcon}>{typeInfo.icon}</span>
            {typeInfo.label} detected
          </span>
        ) : (
          <span style={styles.badgePlaceholder}>
            Paste a link, phone number, email, message — or upload a screenshot
          </span>
        )}
      </div>

      {/* Image preview */}
      {imagePreview && (
        <div style={styles.imagePreviewWrapper}>
          <img
            src={imagePreview}
            alt="Selected screenshot"
            style={styles.imagePreview}
          />
          <button style={styles.removeImageBtn} onClick={handleClear}>
            ✕ Remove
          </button>
        </div>
      )}

      {/* Textarea — hidden when image is selected */}
      {!imagePreview && (
        <div style={styles.textareaWrapper}>
          <textarea
            style={styles.textarea}
            value={value}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            placeholder={
              "e.g.  http://amaz0n-secure.xyz/verify\n" +
              "     +1 900 123 4567\n" +
              "     'You have won $5000! Click here to claim...'"
            }
            rows={5}
            disabled={loading}
            aria-label="Input for scam analysis"
          />
          <span style={styles.charCount}>{value.length} / 2000</span>
        </div>
      )}

      {/* Actions row */}
      <div style={styles.actionsRow}>
        <div style={styles.leftActions}>
          {/* Clear button */}
          {(value.length > 0 || imagePreview) && (
            <button style={styles.clearBtn} onClick={handleClear} type="button">
              Clear
            </button>
          )}

          {/* Hidden file input — triggered by the upload button below */}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/jpeg,image/png,image/webp,image/gif"
            style={{ display: "none" }}
            onChange={handleImageChange}
          />

          {/* Upload screenshot button */}
          {!imagePreview && (
            <button
              style={styles.uploadBtn}
              onClick={() => fileInputRef.current.click()}
              type="button"
              disabled={loading}
              title="Upload a screenshot to analyze"
            >
              📷 Upload Screenshot
            </button>
          )}
        </div>

        {/* Analyze button — only shown for text input, not image */}
        {!imagePreview && (
          <button
            style={{
              ...styles.analyzeBtn,
              opacity: value.trim().length >= 5 && !loading ? 1 : 0.4,
              cursor: value.trim().length >= 5 && !loading ? "pointer" : "not-allowed",
            }}
            onClick={handleSubmit}
            disabled={value.trim().length < 5 || loading}
            type="button"
          >
            {loading ? (
              <span style={styles.loadingInner}>
                <span style={styles.spinner} /> Analyzing…
              </span>
            ) : (
              <>
                <span>Analyze</span>
                <span style={styles.shortcut}>⌘ Enter</span>
              </>
            )}
          </button>
        )}

        {/* Loading state for image analysis */}
        {imagePreview && loading && (
          <button style={{ ...styles.analyzeBtn, opacity: 0.6, cursor: "not-allowed" }} disabled>
            <span style={styles.loadingInner}>
              <span style={styles.spinner} /> Reading image…
            </span>
          </button>
        )}
      </div>
    </div>
  );
};

const styles = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    width: "100%",
  },
  badgeRow: {
    minHeight: "28px",
    display: "flex",
    alignItems: "center",
  },
  badge: {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    background: "rgba(99, 220, 170, 0.12)",
    border: "1px solid rgba(99, 220, 170, 0.3)",
    color: "#63dcaa",
    fontSize: "13px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    padding: "4px 12px",
    borderRadius: "20px",
    letterSpacing: "0.02em",
  },
  badgeIcon: { fontSize: "14px" },
  badgePlaceholder: {
    color: "rgba(255,255,255,0.3)",
    fontSize: "13px",
    fontFamily: "'DM Sans', sans-serif",
    fontStyle: "italic",
  },
  imagePreviewWrapper: {
    position: "relative",
    borderRadius: "12px",
    overflow: "hidden",
    border: "1.5px solid rgba(99,220,170,0.3)",
  },
  imagePreview: {
    width: "100%",
    maxHeight: "240px",
    objectFit: "contain",
    background: "rgba(0,0,0,0.3)",
    display: "block",
  },
  removeImageBtn: {
    position: "absolute",
    top: "10px",
    right: "10px",
    background: "rgba(0,0,0,0.7)",
    border: "1px solid rgba(255,255,255,0.2)",
    borderRadius: "8px",
    color: "#fff",
    fontSize: "12px",
    fontFamily: "'DM Sans', sans-serif",
    padding: "4px 10px",
    cursor: "pointer",
  },
  textareaWrapper: { position: "relative" },
  textarea: {
    width: "100%",
    background: "rgba(255,255,255,0.04)",
    border: "1.5px solid rgba(255,255,255,0.1)",
    borderRadius: "16px",
    padding: "18px 20px",
    color: "#ffffff",
    fontSize: "15px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    lineHeight: "1.7",
    resize: "vertical",
    outline: "none",
    transition: "border-color 0.2s ease, background 0.2s ease",
    boxSizing: "border-box",
    caretColor: "#63dcaa",
  },
  charCount: {
    position: "absolute",
    bottom: "12px",
    right: "16px",
    fontSize: "11px",
    color: "rgba(255,255,255,0.2)",
    fontFamily: "'DM Sans', sans-serif",
    pointerEvents: "none",
  },
  actionsRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    flexWrap: "wrap",
    gap: "8px",
  },
  leftActions: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },
  clearBtn: {
    background: "transparent",
    border: "none",
    color: "rgba(255,255,255,0.35)",
    fontSize: "14px",
    fontFamily: "'DM Sans', sans-serif",
    cursor: "pointer",
    padding: "8px 4px",
    transition: "color 0.2s ease",
    letterSpacing: "0.02em",
  },
  uploadBtn: {
    background: "rgba(255,255,255,0.06)",
    border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: "10px",
    color: "rgba(255,255,255,0.7)",
    fontSize: "13px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    padding: "8px 14px",
    cursor: "pointer",
    transition: "background 0.2s ease, border-color 0.2s ease",
    letterSpacing: "0.02em",
  },
  analyzeBtn: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    background: "linear-gradient(135deg, #63dcaa 0%, #3bb8f5 100%)",
    border: "none",
    borderRadius: "12px",
    color: "#0a0f1e",
    fontSize: "15px",
    fontFamily: "'Syne', sans-serif",
    fontWeight: 700,
    padding: "12px 28px",
    transition: "opacity 0.2s ease, transform 0.15s ease",
    letterSpacing: "0.02em",
  },
  shortcut: {
    fontSize: "11px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    opacity: 0.6,
  },
  loadingInner: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },
  spinner: {
    display: "inline-block",
    width: "14px",
    height: "14px",
    border: "2px solid rgba(10,15,30,0.3)",
    borderTopColor: "#0a0f1e",
    borderRadius: "50%",
    animation: "spin 0.7s linear infinite",
  },
};

export default InputBox;

// We replicate the input type detection logic in the frontend
// so the badge updates instantly without waiting for the API.
const detectType = (input) => {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (/^(https?:\/\/|www\.)|^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/|$)/i.test(trimmed)) return "url";
  if (/^\+?[\d\s\-\(\)]{7,20}$/.test(trimmed)) return "phone";
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) return "email";
  if (trimmed.length > 3) return "text";
  return null;
};

const TYPE_LABELS = {
  url: { label: "URL / Link", icon: "🔗" },
  phone: { label: "Phone Number", icon: "📞" },
  email: { label: "Email Address", icon: "✉️" },
  text: { label: "Message / SMS", icon: "💬" },
};

const InputBox = ({ onAnalyze, onClear, loading }) => {
  const [value, setValue] = useState("");
  const [detectedType, setDetectedType] = useState(null);

  // Update the type badge as the user types
  useEffect(() => {
    setDetectedType(detectType(value));
  }, [value]);

  const handleChange = (e) => {
    setValue(e.target.value);
  };

  const handleSubmit = () => {
    if (value.trim().length >= 5) {
      onAnalyze(value);
    }
  };

  const handleClear = () => {
    setValue("");
    setDetectedType(null);
    onClear();
  };

  const handleKeyDown = (e) => {
    // Ctrl+Enter or Cmd+Enter submits (common UX pattern for textareas)
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      handleSubmit();
    }
  };

  const typeInfo = detectedType ? TYPE_LABELS[detectedType] : null;

  return (
    <div style={styles.wrapper}>
      {/* Type detection badge */}
      <div style={styles.badgeRow}>
        {typeInfo ? (
          <span style={styles.badge}>
            <span style={styles.badgeIcon}>{typeInfo.icon}</span>
            {typeInfo.label} detected
          </span>
        ) : (
          <span style={styles.badgePlaceholder}>
            Paste a link, phone number, email, or suspicious message
          </span>
        )}
      </div>

      {/* Textarea */}
      <div style={styles.textareaWrapper}>
        <textarea
          style={styles.textarea}
          value={value}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          placeholder="e.g.  http://amaz0n-secure.xyz/verify&#10;     +1 900 123 4567&#10;     'You have won $5000! Click here to claim...'"
          rows={5}
          disabled={loading}
          aria-label="Input for scam analysis"
        />
        {/* Character count */}
        <span style={styles.charCount}>{value.length} / 2000</span>
      </div>

      {/* Actions row */}
      <div style={styles.actionsRow}>
        <button
          style={{
            ...styles.clearBtn,
            opacity: value.length > 0 ? 1 : 0,
            pointerEvents: value.length > 0 ? "auto" : "none",
          }}
          onClick={handleClear}
          type="button"
        >
          Clear
        </button>

        <button
          style={{
            ...styles.analyzeBtn,
            opacity: value.trim().length >= 5 && !loading ? 1 : 0.4,
            cursor: value.trim().length >= 5 && !loading ? "pointer" : "not-allowed",
          }}
          onClick={handleSubmit}
          disabled={value.trim().length < 5 || loading}
          type="button"
        >
          {loading ? (
            <span style={styles.loadingInner}>
              <span style={styles.spinner} /> Analyzing…
            </span>
          ) : (
            <>
              <span>Analyze</span>
              <span style={styles.shortcut}>⌘ Enter</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};

// ── Inline styles ────────────────────────────────────────────
// We use inline styles because this is a self-contained component.
// CSS variables defined in App.jsx flow through via var() references.
const styles = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    width: "100%",
  },
  badgeRow: {
    minHeight: "28px",
    display: "flex",
    alignItems: "center",
  },
  badge: {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    background: "rgba(99, 220, 170, 0.12)",
    border: "1px solid rgba(99, 220, 170, 0.3)",
    color: "#63dcaa",
    fontSize: "13px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 500,
    padding: "4px 12px",
    borderRadius: "20px",
    letterSpacing: "0.02em",
    animation: "fadeIn 0.2s ease",
  },
  badgeIcon: {
    fontSize: "14px",
  },
  badgePlaceholder: {
    color: "rgba(255,255,255,0.3)",
    fontSize: "13px",
    fontFamily: "'DM Sans', sans-serif",
    fontStyle: "italic",
  },
  textareaWrapper: {
    position: "relative",
  },
  textarea: {
    width: "100%",
    background: "rgba(255,255,255,0.04)",
    border: "1.5px solid rgba(255,255,255,0.1)",
    borderRadius: "16px",
    padding: "18px 20px",
    color: "#ffffff",
    fontSize: "15px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 300,
    lineHeight: "1.7",
    resize: "vertical",
    outline: "none",
    transition: "border-color 0.2s ease, background 0.2s ease",
    boxSizing: "border-box",
    caretColor: "#63dcaa",
  },
  charCount: {
    position: "absolute",
    bottom: "12px",
    right: "16px",
    fontSize: "11px",
    color: "rgba(255,255,255,0.2)",
    fontFamily: "'DM Sans', sans-serif",
    pointerEvents: "none",
  },
  actionsRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  clearBtn: {
    background: "transparent",
    border: "none",
    color: "rgba(255,255,255,0.35)",
    fontSize: "14px",
    fontFamily: "'DM Sans', sans-serif",
    cursor: "pointer",
    padding: "8px 4px",
    transition: "color 0.2s ease, opacity 0.2s ease",
    letterSpacing: "0.02em",
  },
  analyzeBtn: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    background: "linear-gradient(135deg, #63dcaa 0%, #3bb8f5 100%)",
    border: "none",
    borderRadius: "12px",
    color: "#0a0f1e",
    fontSize: "15px",
    fontFamily: "'Syne', sans-serif",
    fontWeight: 700,
    padding: "12px 28px",
    transition: "opacity 0.2s ease, transform 0.15s ease",
    letterSpacing: "0.02em",
  },
  shortcut: {
    fontSize: "11px",
    fontFamily: "'DM Sans', sans-serif",
    fontWeight: 400,
    opacity: 0.6,
  },
  loadingInner: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },
  spinner: {
    display: "inline-block",
    width: "14px",
    height: "14px",
    border: "2px solid rgba(10,15,30,0.3)",
    borderTopColor: "#0a0f1e",
    borderRadius: "50%",
    animation: "spin 0.7s linear infinite",
  },
};

export default InputBox;
