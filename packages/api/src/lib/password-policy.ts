/**
 * Password strength policy.
 *
 * One definition, applied at every point a password is SET (org creation,
 * user creation, a password reset) so the rules cannot drift between them.
 * Login is not gated — an existing account must still be able to sign in even
 * if its password predates this policy.
 *
 * Rules match the pentest requirement: 8–32 characters, with at least one
 * uppercase letter, one lowercase letter, one digit and one special character.
 */

export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 32;

/** Returns an error message if the password is unacceptable, or null if valid. */
export function validatePassword(password: unknown): string | null {
  if (typeof password !== "string") {
    return "Password is required.";
  }
  // The max length also bounds the hashing work, so an enormous string cannot
  // be used to burn CPU.
  if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
    return `Password must be between ${PASSWORD_MIN} and ${PASSWORD_MAX} characters.`;
  }
  if (!/[A-Z]/.test(password)) return "Password must contain an uppercase letter.";
  if (!/[a-z]/.test(password)) return "Password must contain a lowercase letter.";
  if (!/[0-9]/.test(password)) return "Password must contain a digit.";
  // Anything that is not a letter or digit counts as special.
  if (!/[^A-Za-z0-9]/.test(password)) {
    return "Password must contain a special character.";
  }
  return null;
}
