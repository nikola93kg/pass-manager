// ============================================================
// PASSWORD GENERATOR
// Uses only crypto.getRandomValues — never Math.random()
// ============================================================

import type { PasswordGenOptions } from './types';

const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const DIGITS    = '0123456789';
const SYMBOLS   = '!@#$%^&*()_+-=[]{}|;:,.<>?';

export function generatePassword(options: PasswordGenOptions): string {
  const { length, uppercase, lowercase, digits, symbols } = options;

  let charset = '';
  const required: string[] = [];

  if (uppercase) {
    charset += UPPERCASE;
    required.push(pickRandom(UPPERCASE));
  }
  if (lowercase) {
    charset += LOWERCASE;
    required.push(pickRandom(LOWERCASE));
  }
  if (digits) {
    charset += DIGITS;
    required.push(pickRandom(DIGITS));
  }
  if (symbols) {
    charset += SYMBOLS;
    required.push(pickRandom(SYMBOLS));
  }

  if (charset.length === 0) {
    // Fallback: alphanumeric
    charset = UPPERCASE + LOWERCASE + DIGITS;
  }

  if (length < required.length) {
    throw new Error('Password length too short for selected character sets.');
  }

  // Fill remaining positions
  const remaining = length - required.length;
  const pool: string[] = [...required];

  for (let i = 0; i < remaining; i++) {
    pool.push(pickRandom(charset));
  }

  // Shuffle using Fisher-Yates with crypto.getRandomValues
  return cryptoShuffle(pool).join('');
}

function pickRandom(charset: string): string {
  const buf = new Uint32Array(1);
  const max = Math.floor(0x100000000 / charset.length) * charset.length;
  let rand: number;
  do {
    crypto.getRandomValues(buf);
    rand = buf[0];
  } while (rand >= max); // rejection sampling for uniform distribution
  return charset[rand % charset.length];
}

function cryptoShuffle(arr: string[]): string[] {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const buf = new Uint32Array(1);
    const max = Math.floor(0x100000000 / (i + 1)) * (i + 1);
    let rand: number;
    do {
      crypto.getRandomValues(buf);
      rand = buf[0];
    } while (rand >= max);
    const j = rand % (i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}
