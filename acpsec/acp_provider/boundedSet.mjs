// boundedSet.mjs
// FIFO-bounded set: keeps at most `max` entries, evicts oldest on overflow.
// Drop-in for the subset of Set used by the provider loop (.has / .add / .delete / .size).

export class BoundedSet {
  /** @param {number} max  Maximum entries to retain (default 1000). */
  constructor(max = 1000) {
    if (!Number.isInteger(max) || max <= 0) {
      throw new RangeError(`BoundedSet max must be a positive integer, got ${max}`);
    }
    this.max = max;
    // Map preserves insertion order, giving us O(1) oldest-key access.
    this._m = new Map();
  }

  has(key) {
    return this._m.has(key);
  }

  add(key) {
    // Re-adding an existing key refreshes its recency (delete + re-insert moves it to newest).
    if (this._m.has(key)) this._m.delete(key);
    this._m.set(key, true);
    // Evict oldest while over capacity (handles the case where max was lowered).
    while (this._m.size > this.max) {
      const oldest = this._m.keys().next().value;
      this._m.delete(oldest);
    }
    return this;
  }

  delete(key) {
    return this._m.delete(key);
  }

  get size() {
    return this._m.size;
  }

  clear() {
    this._m.clear();
  }
}
