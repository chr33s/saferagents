export function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const t = new Promise<never>((_, reject) => (timer = setTimeout(() => reject(new Error(label)), ms)));
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}
