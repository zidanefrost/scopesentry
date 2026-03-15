# ScopeSentry

ScopeSentry is a reconnaissance reporting project built around a part of security work I genuinely enjoy: taking messy target notes and turning them into something structured, reviewable, and reusable.

The repo is public-safe by design. The bundled scope and findings are synthetic, and the live mode is limited to lightweight HTTP metadata collection for targets you explicitly own or are authorized to assess.

## What It Does

- reads an authorized URL scope list
- collects either fixture data or live HTTP metadata
- scores missing web security headers and exposed routes
- exports both HTML and JSON reports
- ships with a static microsite so the project is easy to demo publicly

## Why I Built It

In labs and challenge environments, recon data gets noisy fast. I wanted a small tool that would capture the reporting side of that workflow: scope in, evidence out, and no confusion later about what was actually observed.

## Project Structure

- `scopesentry.py`: the CLI pipeline
- `scope.txt`: demo scope list
- `fixtures/authorized_fixture.json`: synthetic target metadata
- `output/`: generated reports
- `index.html`, `styles.css`, `script.js`: project microsite

## What The Project Produces

- an HTML findings report
- a JSON export of the same assessment data
- a small project microsite for portfolio presentation

## Live Collection Scope

The optional live collection mode is intentionally narrow. It can:

- fetch the target URL
- extract a page title
- read response headers
- check for `/.well-known/security.txt`

It is intentionally not a scanner for arbitrary hosts or ports.

## Public-Safety Notes

- Use live mode only on systems you own or are authorized to assess.
- Keep public demos fixture-driven unless you are deliberately documenting your own infrastructure.
- The included fixture data is synthetic so the repo stays safe for a public portfolio.
