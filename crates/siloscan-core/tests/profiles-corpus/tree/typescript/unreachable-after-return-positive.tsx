export function Banner({ text }: { text: string }) {
  if (!text) {
    return <span />;
    console.log('never runs');
  }
  return <strong>{text}</strong>;
}
