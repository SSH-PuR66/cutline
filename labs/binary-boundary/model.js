export function unsigned(value, max = 4294967295n) {
  if (!/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error('Use whole decimal numbers without signs or exponents.');
  const n = BigInt(value);
  if (n > max) throw new Error(`Maximum value is ${max}.`);
  return n;
}
export function inspectRange(total, offset, count) {
  const t=unsigned(total), o=unsigned(offset), n=unsigned(count), sum=o+n;
  return {sum:sum.toString(),wrapped:(sum%4294967296n).toString(),legacy:Number(sum%4294967296n<=t),corrected:Number(o<=t&&n<=t-o)};
}
export function inspectBoolean(value) {
  const n=unsigned(value,255n);
  return {legacy:Number(n!==0n),corrected:n<=1n?Number(n):-1};
}
