# Release process

1. Regenerate schemas and assert no unexpected diff.
2. Run architecture, static security and secret scans.
3. Run the complete test suite with branch coverage.
4. Build and run the meeting demo.
5. Run the synthetic benchmark and preserve its limitations.
6. Build wheel and sdist with a fixed `SOURCE_DATE_EPOCH`.
7. Install the wheel in a clean environment and execute the CLI.
8. Generate SBOM, release manifest, inventory and checksums.

Coverage evidence must report three distinct values from `coverage.json`: statement coverage,
branch coverage, and the combined coverage percentage. The `coverage report --fail-under=85`
gate uses the combined metric when branch measurement is enabled; the combined value must never
be labeled as branch coverage.
9. Verify all release hashes before creating a tag.
10. Do not call the release production-ready before an external pilot and review.
