const exponentByCurrency: Record<string, number> = {
  PKR: 2, USD: 2, EUR: 2, GBP: 2, AED: 2, SAR: 2, CAD: 2, AUD: 2, CNY: 2, JPY: 0,
};
export function currencyExponent(currency: string): number {
  return exponentByCurrency[currency.toUpperCase()] ?? 2;
}
export function formatMoney(minor: number | null | undefined, currency: string): string {
  if (minor === null || minor === undefined || !Number.isSafeInteger(minor)) return "Not available";
  const exponent = currencyExponent(currency);
  const sign = minor < 0 ? "−" : "";
  const absolute = Math.abs(minor);
  const whole = Math.floor(absolute / 10 ** exponent);
  const fraction = exponent ? (absolute % 10 ** exponent).toString().padStart(exponent, "0") : "";
  const grouped = whole.toLocaleString("en-US");
  return `${sign}${currency.toUpperCase()} ${grouped}${exponent ? `.${fraction}` : ""}`;
}
export function amountToMinor(value: string, currency: string): number | null {
  const exp = currencyExponent(currency);
  const pattern = exp === 0 ? /^(\d+)$/ : new RegExp(`^(\\d+)(?:\\.(\\d{1,${exp}}))?$`);
  const match = value.trim().match(pattern);
  if (!match) return null;
  try {
    const scale = 10n ** BigInt(exp);
    const fraction = exp ? BigInt((match[2] ?? "").padEnd(exp, "0")) : 0n;
    const result = BigInt(match[1]) * scale + fraction;
    if (result > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(result);
  } catch {
    return null;
  }
}
