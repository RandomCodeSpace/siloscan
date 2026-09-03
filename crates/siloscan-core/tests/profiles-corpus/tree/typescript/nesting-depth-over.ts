export function walkOver(values: number[]): number {
  let total = 0;
  for (const value of values) {
    for (const value of values) {
      for (const value of values) {
        for (const value of values) {
          for (const value of values) {
            for (const value of values) {
              total += value;
            }
          }
        }
      }
    }
  }
  return total;
}
