function f(a?: { b?: string }): number {
  return a!.b!.length;
}
