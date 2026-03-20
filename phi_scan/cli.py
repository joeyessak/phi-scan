"""Typer CLI entry point for PhiScan."""

import typer

app = typer.Typer(
    name="phi-scan",
    help="PHI/PII Scanner for CI/CD pipelines. HIPAA & FHIR compliant. Local execution only.",
    no_args_is_help=True,
)
