import { describe, expect, it } from 'vitest';
import { dnsPatternMatches, matchHostname } from './hostname';

describe('dnsPatternMatches (RFC 6125/9525 rules)', () => {
  it('exact match, case-insensitive, trailing dot tolerant', () => {
    expect(dnsPatternMatches('www.example.test', 'www.example.test')).toBe(true);
    expect(dnsPatternMatches('WWW.Example.TEST', 'www.example.test')).toBe(true);
    expect(dnsPatternMatches('www.example.test', 'www.example.test.')).toBe(true);
    expect(dnsPatternMatches('www.example.test', 'shop.example.test')).toBe(false);
  });

  it('wildcard matches exactly one leftmost label', () => {
    expect(dnsPatternMatches('*.example.test', 'www.example.test')).toBe(true);
    expect(dnsPatternMatches('*.example.test', 'a.b.example.test')).toBe(false);
    expect(dnsPatternMatches('*.example.test', 'example.test')).toBe(false);
  });

  it('rejects non-leftmost and partial-label wildcards', () => {
    expect(dnsPatternMatches('www.*.test', 'www.example.test')).toBe(false);
    expect(dnsPatternMatches('w*w.example.test', 'www.example.test')).toBe(false);
    expect(dnsPatternMatches('*', 'example.test')).toBe(false);
  });
});

describe('matchHostname (SAN governs; CN never consulted)', () => {
  it('accepts when a SAN dNSName matches', () => {
    const m = matchHostname('www.example.test', ['www.example.test'], 'irrelevant');
    expect(m.ok).toBe(true);
    expect(m.matchedSan).toBe('www.example.test');
  });

  it('rejects when SAN mismatches even though CN matches (deprecated fallback)', () => {
    const m = matchHostname('www.example.test', ['shop.example.test'], 'www.example.test');
    expect(m.ok).toBe(false);
    expect(m.cnWouldHaveMatched).toBe(true);
    expect(m.detail).toContain('deprecated');
  });

  it('rejects when there are no SAN dNSNames, regardless of CN', () => {
    const m = matchHostname('www.example.test', [], 'www.example.test');
    expect(m.ok).toBe(false);
    expect(m.cnWouldHaveMatched).toBe(true);
  });
});
