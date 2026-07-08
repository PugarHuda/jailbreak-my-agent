// Strip C0/C1 controls (ESC -> ANSI terminal-escape injection that can overwrite
// a rendered report line and spoof a result), bidi overrides (Trojan-Source
// visual spoofing), and zero-width chars from untrusted text before it lands in a
// terminal/markdown report. Built from hex ranges so the source stays ASCII (no
// literal control chars in the file).
const UNSAFE = new RegExp(
  "[" +
    ["0000-001f", "007f-009f", "200b-200f", "2028", "2029", "202a-202e", "2060", "2066-2069", "feff", "061c"]
      .map((r) => r.split("-").map((h) => "\\u" + h).join("-"))
      .join("") +
    "]",
  "g",
);

export const stripUnsafe = (s: string): string => String(s).replace(UNSAFE, "");
