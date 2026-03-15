from __future__ import annotations

import argparse
import html
import json
import re
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REQUIRED_HEADERS = {
    "content-security-policy": "Missing CSP",
    "strict-transport-security": "Missing HSTS",
    "x-frame-options": "Missing X-Frame-Options",
    "x-content-type-options": "Missing X-Content-Type-Options",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect safe web metadata for an authorized URL scope and render a report."
    )
    parser.add_argument("--scope", required=True, help="Path to a newline-separated list of URLs.")
    parser.add_argument(
        "--fixtures",
        help="Path to synthetic fixture data for a deterministic portfolio demo.",
    )
    parser.add_argument(
        "--mode",
        choices=["fixtures", "live"],
        default="fixtures",
        help="Use synthetic fixtures or perform live HTTP collection.",
    )
    parser.add_argument("--output", required=True, help="Path to the HTML report output.")
    parser.add_argument("--json-output", required=True, help="Path to the JSON report output.")
    return parser.parse_args()


def load_scope(scope_path: Path) -> list[str]:
    return [
        line.strip()
        for line in scope_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_fixtures(fixture_path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    return {entry["url"]: entry for entry in data}


def title_from_html(body: str) -> str:
    match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return "Untitled Response"
    return re.sub(r"\s+", " ", match.group(1)).strip()


def check_security_txt(url: str) -> bool:
    target = url.rstrip("/") + "/.well-known/security.txt"
    request = Request(target, headers={"User-Agent": "ScopeSentry/1.0"})
    try:
        with urlopen(request, timeout=5) as response:
            return response.status == 200
    except Exception:
        return False


def fetch_live_target(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "ScopeSentry/1.0"})
    start = time.perf_counter()
    headers = {}
    body = ""
    status = 0
    notes = ""

    try:
        with urlopen(request, timeout=8) as response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(200000).decode("utf-8", errors="replace")
    except HTTPError as exc:
        status = exc.code
        headers = {key.lower(): value for key, value in exc.headers.items()}
        body = exc.read(50000).decode("utf-8", errors="replace")
        notes = "HTTP error response collected during authorized metadata fetch."
    except URLError as exc:
        notes = f"Request failed: {exc.reason}"
    except Exception as exc:
        notes = f"Unexpected error during collection: {exc}"

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    title = title_from_html(body) if body else "No HTML title extracted"
    exposures = []

    if "admin" in body.lower():
      exposures.append(
          {"path": "/admin", "severity": "medium", "detail": "The response body referenced 'admin'."}
      )

    technologies = []
    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    if server:
        technologies.append(server)
    if powered_by:
        technologies.append(powered_by)

    result = {
        "url": url,
        "status": status,
        "title": title,
        "headers": headers,
        "technologies": technologies,
        "notes": notes or "Collected via live HTTP mode.",
        "exposures": exposures,
        "security_txt": check_security_txt(url),
        "latency_ms": elapsed_ms,
    }
    return apply_analysis(result)


def apply_analysis(target: dict[str, Any]) -> dict[str, Any]:
    headers = {key.lower(): value for key, value in target.get("headers", {}).items()}
    issues = []
    score = 0

    for header, label in REQUIRED_HEADERS.items():
        if header not in headers:
            issues.append({"severity": "medium", "detail": label})
            score += 15

    for exposure in target.get("exposures", []):
        severity = exposure.get("severity", "low")
        if severity == "high":
            score += 28
        elif severity == "medium":
            score += 16
        else:
            score += 8
        issues.append({"severity": severity, "detail": exposure.get("detail", "Exposed route detected")})

    if not target.get("security_txt", False):
        issues.append({"severity": "low", "detail": "No /.well-known/security.txt detected"})
        score += 5

    status = int(target.get("status", 0) or 0)
    if status >= 500:
        issues.append({"severity": "high", "detail": "Server-side failure observed during metadata collection"})
        score += 20
    elif status == 0:
        issues.append({"severity": "low", "detail": "No live HTTP status collected"})

    target["issues"] = issues
    target["risk_score"] = min(score, 100)
    target["risk_level"] = (
        "high" if score >= 60 else "medium" if score >= 25 else "low"
    )
    return target


def collect_fixture_results(scope: list[str], fixtures: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for url in scope:
        entry = fixtures.get(url)
        if not entry:
            entry = {
                "url": url,
                "status": 0,
                "title": "Missing fixture entry",
                "headers": {},
                "technologies": [],
                "notes": "No matching fixture entry existed for this target.",
                "exposures": [],
                "security_txt": False,
            }
        results.append(apply_analysis(entry))
    return results


def collect_live_results(scope: list[str]) -> list[dict[str, Any]]:
    with ThreadPoolExecutor(max_workers=min(8, len(scope) or 1)) as executor:
        return list(executor.map(fetch_live_target, scope))


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [item["risk_score"] for item in results]
    average = round(statistics.mean(scores), 2) if scores else 0
    highest = max(scores, default=0)
    high_risk_targets = sum(1 for item in results if item["risk_level"] == "high")
    return {
        "targets": len(results),
        "average_risk_score": average,
        "highest_risk_score": highest,
        "high_risk_targets": high_risk_targets,
    }


def render_html_report(results: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    cards = []
    for item in results:
        issue_markup = "".join(
            f"<li><strong>{html.escape(issue['severity'].upper())}</strong> {html.escape(issue['detail'])}</li>"
            for issue in item["issues"]
        )
        tech_markup = ", ".join(html.escape(tech) for tech in item.get("technologies", [])) or "No fingerprint"
        cards.append(
            f"""
            <article class="target-card risk-{html.escape(item['risk_level'])}">
              <div class="card-head">
                <div>
                  <p class="target-url">{html.escape(item['url'])}</p>
                  <h2>{html.escape(item['title'])}</h2>
                </div>
                <div class="risk-pill">{html.escape(item['risk_level']).upper()} {item['risk_score']}</div>
              </div>
              <p class="meta-line">Status {item['status']} | Tech {tech_markup}</p>
              <p class="note-line">{html.escape(item.get('notes', ''))}</p>
              <ul class="issue-list">{issue_markup}</ul>
            </article>
            """
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ScopeSentry Report</title>
  <style>
    body {{
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f3f7f9;
      color: #102231;
    }}
    main {{
      width: min(1100px, calc(100% - 2rem));
      margin: 0 auto;
      padding: 2rem 0 3rem;
    }}
    .hero {{
      padding: 1.5rem;
      background: #ffffff;
      border-radius: 24px;
      box-shadow: 0 16px 36px rgba(16, 34, 49, 0.12);
      margin-bottom: 1rem;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 1rem;
      margin: 1rem 0 1.5rem;
    }}
    .stat {{
      background: #eef5f7;
      padding: 1rem;
      border-radius: 18px;
    }}
    .results {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1rem;
    }}
    .target-card {{
      padding: 1.2rem;
      background: #ffffff;
      border-radius: 20px;
      box-shadow: 0 16px 32px rgba(16, 34, 49, 0.08);
      border-left: 8px solid #4e7d9d;
    }}
    .risk-high {{ border-left-color: #b94c3b; }}
    .risk-medium {{ border-left-color: #c08b2a; }}
    .risk-low {{ border-left-color: #2e8b67; }}
    .card-head {{
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: start;
    }}
    h1, h2 {{ margin: 0; }}
    h1 {{ font-size: 2.2rem; }}
    h2 {{ font-size: 1.2rem; margin-top: 0.35rem; }}
    .target-url, .meta-line, .note-line {{
      color: #4d6171;
      line-height: 1.6;
    }}
    .risk-pill {{
      white-space: nowrap;
      padding: 0.5rem 0.8rem;
      border-radius: 999px;
      background: #102231;
      color: #ffffff;
      font-size: 0.85rem;
      font-weight: bold;
    }}
    .issue-list {{
      padding-left: 1.2rem;
      margin: 0.9rem 0 0;
      line-height: 1.7;
    }}
    @media (max-width: 900px) {{
      .grid, .results {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>ScopeSentry Report</h1>
      <p>This report was generated by the public-safe ScopeSentry demo pipeline.</p>
      <div class="grid">
        <div class="stat"><strong>{summary['targets']}</strong><br>Targets in scope</div>
        <div class="stat"><strong>{summary['average_risk_score']}</strong><br>Average risk score</div>
        <div class="stat"><strong>{summary['highest_risk_score']}</strong><br>Highest risk score</div>
        <div class="stat"><strong>{summary['high_risk_targets']}</strong><br>High risk targets</div>
      </div>
    </section>
    <section class="results">
      {''.join(cards)}
    </section>
  </main>
</body>
</html>
"""


def write_outputs(results: list[dict[str, Any]], summary: dict[str, Any], html_path: Path, json_path: Path) -> None:
    html_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(render_html_report(results, summary), encoding="utf-8")
    json_path.write_text(
        json.dumps({"summary": summary, "results": results}, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    args = parse_args()
    scope_path = Path(args.scope)
    output_path = Path(args.output)
    json_output_path = Path(args.json_output)

    if not scope_path.exists():
        print(f"Scope file not found: {scope_path}", file=sys.stderr)
        return 1

    scope = load_scope(scope_path)
    if not scope:
        print("The scope file did not contain any targets.", file=sys.stderr)
        return 1

    if args.mode == "fixtures":
        if not args.fixtures:
            print("Fixture mode requires --fixtures.", file=sys.stderr)
            return 1
        fixture_path = Path(args.fixtures)
        if not fixture_path.exists():
            print(f"Fixture file not found: {fixture_path}", file=sys.stderr)
            return 1
        fixtures = load_fixtures(fixture_path)
        results = collect_fixture_results(scope, fixtures)
    else:
        results = collect_live_results(scope)

    summary = build_summary(results)
    write_outputs(results, summary, output_path, json_output_path)

    print(f"Generated {len(results)} results")
    print(f"Average risk score: {summary['average_risk_score']}")
    print(f"High risk targets: {summary['high_risk_targets']}")
    print(f"HTML report: {output_path}")
    print(f"JSON report: {json_output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
