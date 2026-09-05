function f(): number {
  try {
    return 1;
  } finally {
    cleanup();
  }
}
