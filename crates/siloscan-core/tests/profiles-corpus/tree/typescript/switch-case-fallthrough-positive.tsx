export function Icon({ kind }: { kind: string }) {
  const out: string[] = [];
  switch (kind) {
    case "a":
      out.push("a");
    case "b":
      out.push("b");
      break;
  }
  return <span>{out.join("")}</span>;
}
