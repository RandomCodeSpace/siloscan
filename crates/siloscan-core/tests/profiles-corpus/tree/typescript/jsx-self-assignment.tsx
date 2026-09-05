export function Badge({ label }: { label: string }) {
  const icon = <img src="/icon.png" alt="" />;
  label = label;
  return <span className="badge">{icon}{label}</span>;
}
