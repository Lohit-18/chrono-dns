-- ===========================================================================
--  Chrono-DNS :: seed threat intelligence + allowlist  (SQLite)
--  ---------------------------------------------------------------------
--  NOTE ON INDICATORS
--  Every "malicious" indicator below is either an RFC 2606 / RFC 6761
--  reserved documentation name, or an obviously fictional lab domain used by
--  the bundled simulator. Nothing here points at a real third party.
--  Drop your own feed in with:  chronodns intel import <file.csv>
-- ===========================================================================

-- --- Known-bad zones used by the bundled attack simulator ------------------
INSERT OR IGNORE INTO threat_intel
    (indicator, ioc_type, category, severity, confidence, source, notes) VALUES
('tunnel.example',        'zone', 'tunnel',   9, 0.97, 'lab',   'iodine-style tunnel endpoint (simulated)'),
('exfil.example',         'zone', 'tunnel',   9, 0.96, 'lab',   'dnscat2-style exfil zone (simulated)'),
('c2.example',            'zone', 'c2',      10, 0.99, 'lab',   'beaconing C2 rendezvous (simulated)'),
('dga-sink.example',      'zone', 'dga',      8, 0.90, 'lab',   'DGA sinkhole zone (simulated)'),
('malware-test.invalid',  'zone', 'malware',  9, 0.95, 'lab',   'reserved TLD, never resolvable'),
('phish.test',            'zone', 'phishing', 7, 0.88, 'lab',   'credential harvesting (simulated)');

-- --- High-abuse TLDs: not blocked outright, just scored up -----------------
INSERT OR IGNORE INTO threat_intel
    (indicator, ioc_type, category, severity, confidence, source, notes) VALUES
('tk',      'tld', 'malware', 6, 0.60, 'heuristic', 'free registration, very high abuse rate'),
('ml',      'tld', 'malware', 6, 0.58, 'heuristic', 'free registration'),
('ga',      'tld', 'malware', 6, 0.58, 'heuristic', 'free registration'),
('cf',      'tld', 'malware', 6, 0.57, 'heuristic', 'free registration'),
('gq',      'tld', 'malware', 6, 0.57, 'heuristic', 'free registration'),
('top',     'tld', 'malware', 5, 0.52, 'heuristic', 'bulk registration, common in DGA feeds'),
('xyz',     'tld', 'malware', 5, 0.50, 'heuristic', 'bulk registration'),
('monster', 'tld', 'malware', 5, 0.50, 'heuristic', 'bulk registration'),
('cyou',    'tld', 'malware', 5, 0.50, 'heuristic', 'bulk registration'),
('quest',   'tld', 'malware', 5, 0.48, 'heuristic', 'bulk registration');

-- --- Allowlist: the services that legitimately look "weird" ----------------
-- Long, high-entropy hostnames are NORMAL for CDNs, cloud storage, AV
-- lookups and certificate transparency. Without these entries a real
-- deployment drowns in false positives on day one.
INSERT OR IGNORE INTO allowlist (pattern, match_type, reason) VALUES
('in-addr.arpa',          'suffix', 'reverse DNS'),
('ip6.arpa',              'suffix', 'reverse DNS v6'),
('local',                 'suffix', 'mDNS / link-local'),
('localhost',             'exact',  'loopback'),
('akamaiedge.net',        'suffix', 'CDN: long hashed hostnames are normal'),
('akamai.net',            'suffix', 'CDN'),
('cloudfront.net',        'suffix', 'CDN'),
('amazonaws.com',         'suffix', 'cloud storage: bucket names look random'),
('azureedge.net',         'suffix', 'CDN'),
('windowsupdate.com',     'suffix', 'OS update channel'),
('cloudflare.com',        'suffix', 'CDN / resolver'),
('cloudflare-dns.com',    'suffix', 'DoH endpoint'),
('googleapis.com',        'suffix', 'cloud APIs'),
('gstatic.com',           'suffix', 'static assets'),
('gvt1.com',              'suffix', 'Google update servers'),
('fastly.net',            'suffix', 'CDN'),
('cdn77.org',             'suffix', 'CDN'),
('sophosxl.net',          'suffix', 'AV reputation lookups are hash-encoded by design'),
('spamhaus.org',          'suffix', 'RBL lookups are hash-encoded by design'),
('dnsbl.org',             'suffix', 'RBL lookups'),
('mcafee.com',            'suffix', 'AV reputation lookups'),
('trendmicro.com',        'suffix', 'AV reputation lookups'),
('ntp.org',               'suffix', 'time sync'),
('example.com',           'suffix', 'RFC 2606 documentation domain — benign simulator zone'),
('example.net',           'suffix', 'RFC 2606 documentation domain'),
('example.org',           'suffix', 'RFC 2606 documentation domain');

-- --- A few pre-trusted baselines so the demo starts warm -------------------
INSERT OR IGNORE INTO domain_baseline
    (registrable, query_count, unique_subdomains, mean_entropy, mean_qname_len, is_trusted)
VALUES
('example.com', 5000, 42, 2.85, 18.0, 1),
('example.net', 3200, 18, 2.70, 16.0, 1),
('example.org', 2800, 12, 2.66, 17.0, 1);
