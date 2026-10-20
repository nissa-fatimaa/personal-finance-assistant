import { describe, expect, it } from "vitest";
import { amountToMinor, currencyExponent, formatMoney } from "./money";

describe("amountToMinor (string -> integer minor units, no floats)", () => {
  it.each([
    ["850", "PKR", 85000],
    ["850.5", "PKR", 85050],
    ["850.05", "PKR", 85005],
    ["0.01", "USD", 1],
    ["  12.30  ", "EUR", 1230],
    ["1500", "JPY", 1500],
  ])("parses %s %s", (input, currency, expected) => {
    expect(amountToMinor(input, currency)).toBe(expected);
  });

  it("avoids binary floating-point error", () => {
    // 0.1 + 0.2 style inputs must be exact.
    expect(amountToMinor("0.29", "USD")).toBe(29);
    expect(amountToMinor("1.15", "USD")).toBe(115);
    expect(amountToMinor("4.35", "USD")).toBe(435);
  });

  it.each([
    ["12.345", "USD"], // more decimals than the currency allows
    ["12.5", "JPY"], // JPY has no minor unit
    ["-5", "PKR"],
    ["1,000", "PKR"],
    ["1e3", "PKR"],
    ["", "PKR"],
    ["abc", "PKR"],
    [".5", "USD"],
  ])("rejects %j for %s", (input, currency) => {
    expect(amountToMinor(input, currency)).toBeNull();
  });

  it("rejects values beyond the safe integer range instead of losing precision", () => {
    expect(amountToMinor("90071992547409.92", "USD")).toBeNull();
    expect(amountToMinor("90071992547409.91", "USD")).toBe(Number.MAX_SAFE_INTEGER);
  });
});

describe("formatMoney", () => {
  it("formats with grouping and the currency exponent", () => {
    expect(formatMoney(123456789, "PKR")).toBe("PKR 1,234,567.89");
    expect(formatMoney(5, "usd")).toBe("USD 0.05");
    expect(formatMoney(1500, "JPY")).toBe("JPY 1,500");
  });
  it("uses a real minus sign for negatives", () => {
    expect(formatMoney(-2550, "EUR")).toBe("−EUR 25.50");
  });
  it("never shows an invented number for missing or unsafe values", () => {
    expect(formatMoney(null, "PKR")).toBe("Not available");
    expect(formatMoney(undefined, "PKR")).toBe("Not available");
    expect(formatMoney(1.5, "PKR")).toBe("Not available");
    expect(formatMoney(Number.MAX_SAFE_INTEGER + 2, "PKR")).toBe("Not available");
  });
  it("knows every supported exponent", () => {
    expect(currencyExponent("JPY")).toBe(0);
    for (const c of ["PKR", "USD", "EUR", "GBP", "AED", "SAR", "CAD", "AUD", "CNY"]) {
      expect(currencyExponent(c)).toBe(2);
    }
  });
});
