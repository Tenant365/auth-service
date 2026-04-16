export const generateRandomSecret = (length: number) => {
  return crypto.getRandomValues(new Uint8Array(length)).toString();
};
