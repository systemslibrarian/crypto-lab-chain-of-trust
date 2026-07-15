import { describe, expect, it } from 'vitest';
import { dnsNameInSubtree } from './nameconstraints';

describe('dnsNameInSubtree (RFC 5280 §4.2.1.10)', () => {
  it('name equals base', () => {
    expect(dnsNameInSubtree('example.test', 'example.test')).toBe(true);
  });

  it('labels prepended to the left are within the subtree', () => {
    expect(dnsNameInSubtree('www.example.test', 'example.test')).toBe(true);
    expect(dnsNameInSubtree('a.b.example.test', 'example.test')).toBe(true);
  });

  it('suffix must fall on a label boundary', () => {
    expect(dnsNameInSubtree('badexample.test', 'example.test')).toBe(false);
  });

  it('unrelated names are outside', () => {
    expect(dnsNameInSubtree('www.example.test', 'internal.test')).toBe(false);
  });

  it('case-insensitive; tolerates a leading dot on the base', () => {
    expect(dnsNameInSubtree('WWW.Example.TEST', '.example.test')).toBe(true);
  });
});
