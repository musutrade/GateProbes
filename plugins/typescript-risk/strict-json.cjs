"use strict";
const assert = require("node:assert/strict");
// Parse JSON without losing duplicate field or integer-precision information.
module.exports = function parse(text) {
  let offset = 0;
  const whitespace = () => {
    while (/[ \t\r\n]/.test(text[offset] || "") && offset < text.length)
      offset++;
  };
  function string() {
    const start = offset++;
    while (offset < text.length) {
      const character = text[offset++];
      if (character === "\\") offset++;
      else if (character === '"') return JSON.parse(text.slice(start, offset));
    }
    throw new Error("unterminated JSON string");
  }
  function value(depth) {
    assert(depth < 128, "JSON nesting limit exceeded");
    whitespace();
    const next = text[offset];
    if (next === '"') return string();
    if (next === "{") {
      offset++;
      whitespace();
      const result = Object.create(null),
        keys = new Set();
      if (text[offset] === "}") {
        offset++;
        return result;
      }
      while (true) {
        whitespace();
        assert.equal(text[offset], '"', "expected JSON key");
        const key = string();
        assert(!keys.has(key), "duplicate JSON key");
        keys.add(key);
        whitespace();
        assert.equal(text[offset++], ":", "expected JSON colon");
        result[key] = value(depth + 1);
        whitespace();
        const separator = text[offset++];
        if (separator === "}") return result;
        assert.equal(separator, ",", "expected JSON object separator");
      }
    }
    if (next === "[") {
      offset++;
      whitespace();
      const result = [];
      if (text[offset] === "]") {
        offset++;
        return result;
      }
      while (true) {
        result.push(value(depth + 1));
        whitespace();
        const separator = text[offset++];
        if (separator === "]") return result;
        assert.equal(separator, ",", "expected JSON array separator");
      }
    }
    const match =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        text.slice(offset),
      );
    assert(match, "invalid JSON value");
    offset += match[0].length;
    const result = JSON.parse(match[0]);
    if (typeof result === "number")
      assert(Number.isSafeInteger(result), "non-integer or unsafe JSON number");
    return result;
  }
  const result = value(0);
  whitespace();
  assert.equal(offset, text.length, "trailing JSON input");
  return result;
};
