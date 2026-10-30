# Loon rule lists

This repository builds one Loon `.list` for every `rule-providers` definition in
[`home.yaml`](https://github.com/yzzhaophys/clash-config-public/blob/main/home.yaml).
The build includes definitions and `RULE-SET` references whose lines are commented
out in `home.yaml`. It does not change that file or enable those rules in Mihomo.

GitHub Actions downloads the public upstream YAML for each provider. For an MRS
provider it uses the same-name YAML published by that upstream. It converts the
payload to Loon rules and publishes all lists in one commit only after every
provider succeeds. A failed build leaves the previous lists available.
There is no intermediate ruleset mirror. The published `.list` files correspond
to the upstream YAML fetched for that successful build; the separate MRS binaries
are not decoded or compared by this builder. The current configuration has 238
providers and 237 `RULE-SET` references; one provider is not used for routing.

Current upstream exceptions are explicit in the output: `R-ads-add-ip` has an
empty YAML payload; `R-fakeipfilter` contains the invalid domain entry
`+.Mijia Cloud`; and `R-bankHK` / `R-bankUS` contain 13 wildcard patterns that
cannot be represented in Loon without changing their match scope. The lists
comment out these known entries and retain the other rules. Any other
unsupported entry fails the build.

Run locally:

```sh
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 build.py --home /path/to/clash-config-public/home.yaml --output lists
```

The list files contain match conditions, not policies. Assign each file a Loon
`policy` in `[Remote Rule]`. Loon checks domain and IP rules in its own order,
so compare rule matches in the app before replacing an existing configuration.
Converting `.foo` requires Loon build 1008 or later for `DOMAIN-WILDCARD`.
