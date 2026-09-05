export function Label({ text }: { text: string }) {
  return <em>{render(text)}</em>;
  function render(value: string): string {
    return value.trim();
  }
}

export function Spacer() {
  const width = 8;
  return <span style={{ width }} />;
}
