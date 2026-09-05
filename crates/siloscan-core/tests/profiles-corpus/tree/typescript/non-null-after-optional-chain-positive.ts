function f(a?: { b?: string }): number {
  return a?.b!.length;
}

function g(a?: string[]): number {
  return a?.[0]!.length;
}
