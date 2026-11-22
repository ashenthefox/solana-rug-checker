/** Join market fields without separators for unavailable values. */
export function marketLine(parts) {
  return parts.filter((part) => part != null && part !== "").join("  ·  ");
}
