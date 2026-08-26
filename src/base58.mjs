const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const INDEX = new Map([...ALPHABET].map((char, index) => [char, index]));

export function encodeBase58(bytes) {
  const input = Buffer.from(bytes);
  let zeros = 0;
  while (zeros < input.length && input[zeros] === 0) zeros += 1;
  let number = input.length ? BigInt(`0x${input.toString("hex") || "0"}`) : 0n;
  let encoded = "";
  while (number > 0n) {
    encoded = ALPHABET[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  return "1".repeat(zeros) + encoded;
}

export function decodeBase58(value) {
  if (typeof value !== "string" || value.length === 0)
    throw new Error("Base58 value is required");
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;

  let number = 0n;
  for (let i = zeros; i < value.length; i += 1) {
    const digit = INDEX.get(value[i]);
    if (digit === undefined)
      throw new Error(`Invalid Base58 character: ${value[i]}`);
    number = number * 58n + BigInt(digit);
  }
  let decoded = Buffer.alloc(0);
  if (number > 0n) {
    let hex = number.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    decoded = Buffer.from(hex, "hex");
  }
  return Buffer.concat([Buffer.alloc(zeros), decoded]);
}
