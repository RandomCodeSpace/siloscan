export function pick(kind: string, out: string[]): void {
  switch (kind) {
    case "a":
      out.push("a");
      break;
    case "b":
      out.push("b");
      break;
  }
}
