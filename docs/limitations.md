# Limitations
- Regex patterns cannot cover every secret format; entropy can false-positive or miss structured secrets.
- Username detection only covers `/home/<name>/` paths.
- Canary tests only check complete canary survival; zero leaks is not zero risk.
- Pseudonym mappings are in process memory and are not encrypted.
- Ollama receives only the sanitized text supplied to its opt-in panel; trust the configured endpoint.
- Keyword/reference overlap is not semantic diagnosis accuracy.
- Review sanitized output manually; this is not a security guarantee.
