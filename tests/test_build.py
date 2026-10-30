import unittest

from build import convert_domain, convert_ip, convert_provider, definitions_from_home


class BuildTests(unittest.TestCase):
    HOME = """rule-anchor:
  domain: &domain {type: http, behavior: domain, format: yaml}
rule-providers:
  R-active: {<<: *domain, url: 'https://raw.githubusercontent.com/example/repo/main/active.yaml'}
  #R-disabled: {<<: *domain, url: 'https://raw.githubusercontent.com/example/repo/main/disabled.yaml'}
rules:
  - RULE-SET,R-active,Proxy
  #- RULE-SET,R-disabled,REJECT-DROP
  - MATCH,Final
"""

    def test_commented_providers_and_rules_are_included(self):
        providers, refs, commented_providers, commented_rules = definitions_from_home(self.HOME)
        self.assertEqual(list(providers), ["R-active", "R-disabled"])
        self.assertEqual(refs, ["R-active", "R-disabled"])
        self.assertEqual(commented_providers, ["R-disabled"])
        self.assertEqual(commented_rules, ["R-disabled"])

    def test_missing_reference_fails(self):
        with self.assertRaisesRegex(ValueError, "missing providers"):
            definitions_from_home(self.HOME.replace("R-disabled,REJECT-DROP", "R-missing,REJECT-DROP"))

    def test_domain_conversion_preserves_scope(self):
        self.assertEqual(convert_domain("foo.example"), "DOMAIN,foo.example")
        self.assertEqual(convert_domain("+.example.com"), "DOMAIN-SUFFIX,example.com")
        self.assertEqual(convert_domain(".example.com"), "DOMAIN-WILDCARD,*.example.com")
        with self.assertRaisesRegex(ValueError, "cannot be converted exactly"):
            convert_domain("*.example.com")

    def test_ip_conversion_and_payload(self):
        self.assertEqual(convert_ip("2001:db8::/32"), "IP-CIDR6,2001:db8::/32,no-resolve")
        self.assertEqual(
            convert_provider({"behavior": "ipcidr"}, "payload: ['10.0.0.0/8', '10.0.0.0/8']"),
            "IP-CIDR,10.0.0.0/8,no-resolve\n",
        )

    def test_known_upstream_exceptions_are_visible(self):
        self.assertEqual(
            convert_provider({"behavior": "ipcidr"}, "payload: null", "R-ads-add-ip"),
            "# Upstream payload is empty.\n",
        )
        self.assertIn(
            "# Skipped invalid upstream item: +.Mijia Cloud",
            convert_provider({"behavior": "domain"}, "payload: ['+.Mijia Cloud']", "R-fakeipfilter"),
        )

    def test_bank_wildcards_are_skipped_but_other_entries_are_kept(self):
        bank_patterns = {
            "R-bankHK": [
                "+.vam-hk.*.vv1865.com",
                "+.standchartbank.*.*.*",
                "+.standchartbank.*.*",
            ],
            "R-bankUS": [
                "+.vam-us.*.vv1865.com",
                "+.bankofamerica.*",
                "+.bankofamerica.*.*",
                "+.bankofamerica.*.*.*",
                "+.bankofamerica1.*",
                "+.bankofamerica1.*.*",
                "+.bankofamerica1.*.*.*",
                "+.eastwestbank.*",
                "+.eastwestbank.*.*",
                "+.eastwestbank.*.*.*",
            ],
        }
        for name, patterns in bank_patterns.items():
            payload = ["valid.example", *patterns]
            source = "payload:\n" + "".join(f"  - '{value}'\n" for value in payload)
            output = convert_provider({"behavior": "domain"}, source, name).splitlines()
            self.assertEqual(output[0], "DOMAIN,valid.example")
            self.assertEqual(
                output[1:],
                [f"# Skipped unsupported wildcard pattern: {value}" for value in patterns],
            )

    def test_unknown_wildcard_patterns_still_fail(self):
        with self.assertRaisesRegex(ValueError, "invalid domain entry"):
            convert_provider(
                {"behavior": "domain"},
                "payload: ['+.example.*.com']",
                "R-other",
            )


if __name__ == "__main__":
    unittest.main()
