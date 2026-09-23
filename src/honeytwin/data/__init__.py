"""Configuration files that ship with HoneyTwin.

`defaults.yaml` and `nmap_profiles.yaml` live inside the package so
`importlib.resources` can read them from a source checkout and an
installed wheel alike. Operators override them with their own config
file rather than editing these (see the `config` capability).
"""
