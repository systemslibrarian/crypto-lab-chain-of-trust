/**
 * RFC 6125 / RFC 9525 server-identity matching for DNS names.
 *
 * Policy implemented here (and stated in the UI):
 *  - Only SAN dNSName entries decide the match. The subject CN is NEVER
 *    consulted for the verdict — RFC 6125 §6.4.4 allows CN only when no SAN
 *    dNSName exists, and RFC 9525 (and Chrome since 58, 2017) removed the CN
 *    fallback entirely. We compute whether CN *would* have matched purely so
 *    the UI can show what a legacy verifier would have done.
 *  - Wildcards: '*' must be the entire leftmost label ("*.example.test");
 *    it matches exactly one label and never the bare parent domain.
 *    Partial-label wildcards ("f*o.example.test") are not implemented.
 */
export interface HostnameMatch {
  ok: boolean;
  matchedSan: string | null;
  sanDnsNames: string[];
  cn: string | null;
  /** True if a deprecated CN fallback would have (wrongly) matched. */
  cnWouldHaveMatched: boolean;
  detail: string;
}

function normalize(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, '');
}

/** Does one SAN dNSName pattern cover `host`? Exported for tests. */
export function dnsPatternMatches(pattern: string, host: string): boolean {
  const p = normalize(pattern);
  const h = normalize(host);
  if (p === '' || h === '') return false;
  if (!p.includes('*')) return p === h;
  // Wildcard: only "*.<rest>" (whole leftmost label) is honored.
  if (!p.startsWith('*.') || p.slice(1).includes('*')) return false;
  const rest = p.slice(2);
  if (!h.endsWith('.' + rest)) return false;
  const firstLabel = h.slice(0, h.length - rest.length - 1);
  // exactly one label: non-empty, no dots
  return firstLabel.length > 0 && !firstLabel.includes('.');
}

export function matchHostname(host: string, sanDnsNames: string[], cn: string | null): HostnameMatch {
  const matchedSan = sanDnsNames.find((p) => dnsPatternMatches(p, host)) ?? null;
  const cnWouldHaveMatched = cn !== null && dnsPatternMatches(cn, host);
  const ok = matchedSan !== null;

  let detail: string;
  if (ok) {
    detail = `Host "${host}" matches SAN dNSName "${matchedSan}".`;
  } else if (sanDnsNames.length === 0) {
    detail =
      `The certificate has no SAN dNSName entries, so it identifies no host. ` +
      `CN${cn ? ` ("${cn}")` : ''} is not consulted: RFC 9525 removed the CN fallback.`;
  } else {
    detail =
      `Host "${host}" matches none of the SAN dNSNames [${sanDnsNames.join(', ')}].` +
      (cnWouldHaveMatched
        ? ` The subject CN ("${cn}") DOES name this host — a pre-2017 verifier using the deprecated CN ` +
          `fallback would have accepted it. RFC 6125 §6.4.4 only ever allowed CN when no SAN dNSName is ` +
          `present, and RFC 9525 / modern browsers ignore CN entirely, so the match fails.`
        : '');
  }
  return { ok, matchedSan, sanDnsNames, cn, cnWouldHaveMatched, detail };
}
