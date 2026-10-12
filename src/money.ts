/** An amount in integer minor units (cents for USD, yen for JPY). Never a float. */
export interface Money { currency: string; minor: number }

const digitsCache = new Map<string, number>();
export function fractionDigits(currency: string) {
  let d = digitsCache.get(currency);
  if (d === undefined) {
    d = new Intl.NumberFormat("en-US", { style: "currency", currency }).resolvedOptions().maximumFractionDigits ?? 2;
    digitsCache.set(currency, d);
  }
  return d;
}

/** money("USD", "149.99") → { currency: "USD", minor: 14999 }. Refuses amounts that need rounding. */
export function money(currency: string, major: number | string): Money {
  if (!/^[A-Z]{3}$/.test(currency)) throw new RangeError(`Invalid currency ${currency}`);
  const text = String(major);
  const m = /^(\d+)(?:\.(\d+))?$/.exec(text);
  if (!m) throw new RangeError(`Invalid amount ${text}`);
  const digits = fractionDigits(currency);
  const frac = (m[2] ?? "").replace(/0+$/, "");
  if (frac.length > digits) throw new RangeError(`${text} has more precision than ${currency} allows`);
  const minor = Number(m[1]) * 10 ** digits + Number(frac.padEnd(digits, "0") || 0);
  if (!Number.isSafeInteger(minor)) throw new RangeError(`Amount ${text} is too large`);
  return { currency, minor };
}

export function formatMoney(m: Money) {
  const digits = fractionDigits(m.currency);
  return new Intl.NumberFormat("en-US", { style: "currency", currency: m.currency }).format(m.minor / 10 ** digits);
}
