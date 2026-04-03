from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ghost_recon.benchmarking import (
    BENCHMARK_DOMAINS,
    compare_metrics,
    classify_result_blocker,
    current_timestamp,
    preservation_shortfalls,
    registry_truth_rows,
    render_benchmark_markdown,
    render_preservation_audit_markdown,
    render_provider_diagnostics_markdown,
    render_release_gate_markdown,
    render_registry_truth_markdown,
    result_map,
    run_benchmark_batch,
    save_json,
    save_markdown,
    scan_result_row,
)
from ghost_recon.sources.registry import SourceRegistry
from tools.provider_diagnostics import run_diagnostics


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Recon benchmark harness")
    parser.add_argument("--mode", default="deep", choices=["fast", "balanced", "deep", "turbo"])
    parser.add_argument("--out-dir", default="benchmark_runs")
    args = parser.parse_args()

    stamp = current_timestamp()
    out_root = Path(args.out_dir) / stamp
    out_root.mkdir(parents=True, exist_ok=True)

    single_batch = await run_benchmark_batch(BENCHMARK_DOMAINS, mode=args.mode, results_root=out_root, concurrent=False)
    concurrent_batch = await run_benchmark_batch(BENCHMARK_DOMAINS, mode=args.mode, results_root=out_root, concurrent=True)
    provider_rows = await run_diagnostics()

    single_map = result_map(single_batch)
    concurrent_map = result_map(concurrent_batch)

    single_rows = [compare_metrics(domain, single_map.get(domain, {})) for domain in BENCHMARK_DOMAINS]
    concurrent_rows = [
        compare_metrics(
            domain,
            concurrent_map.get(domain, {}),
            single_scan_reference=single_map.get(domain, {}),
        )
        for domain in BENCHMARK_DOMAINS
    ]
    release_rows = [
        scan_result_row(domain, single_map.get(domain, {}), concurrent_map.get(domain, {}))
        for domain in BENCHMARK_DOMAINS
    ]
    failures = [row for row in release_rows if row.get("status") != "PASS"]
    verdict = "READY FOR API KEY TESTING" if not failures else "NOT READY FOR API KEY TESTING"

    registry_rows = registry_truth_rows(SourceRegistry(profile="balanced", api_keys={}, force_no_keys=True).list_sources())

    benchmark_payload = {
        "single": single_batch,
        "concurrent": concurrent_batch,
        "provider_diagnostics": provider_rows,
        "single_comparison": single_rows,
        "concurrent_comparison": concurrent_rows,
        "release_gate": release_rows,
        "verdict": verdict,
    }
    save_json(out_root / "benchmarks.json", benchmark_payload)
    save_json(out_root / "provider_diagnostics.json", {"rows": provider_rows})
    save_json(out_root / "registry_truth.json", {"rows": registry_rows})
    save_markdown(out_root / "single_scan.md", render_benchmark_markdown("Ghost Recon Single-Scan Benchmarks", single_rows))
    save_markdown(out_root / "concurrent_scan.md", render_benchmark_markdown("Ghost Recon Concurrent Benchmarks", concurrent_rows))
    save_markdown(out_root / "provider_diagnostics.md", render_provider_diagnostics_markdown(provider_rows))
    save_markdown(
        out_root / "preservation_audit.md",
        "\n".join(
            [
                render_preservation_audit_markdown("Ghost Recon Preservation Audit — Single Scan", single_batch.get("results", [])),
                render_preservation_audit_markdown("Ghost Recon Preservation Audit — Concurrent Scan", concurrent_batch.get("results", [])),
                "# Blocker Classification",
                "",
                "| Domain | Single blocker | Concurrent blocker | Single preservation shortfalls | Concurrent preservation shortfalls |",
                "|---|---|---|---|---|",
            ]
            + [
                (
                    f"| `{domain}` | "
                    f"`{classify_result_blocker(single_row.get('metrics', {}), single_row.get('preservation', {}), single_row.get('provider_summary', {}))}` | "
                    f"`{classify_result_blocker(concurrent_row.get('metrics', {}), concurrent_row.get('preservation', {}), concurrent_row.get('provider_summary', {}))}` | "
                    f"`{'; '.join(preservation_shortfalls(single_row.get('preservation', {}))) or 'none'}` | "
                    f"`{'; '.join(preservation_shortfalls(concurrent_row.get('preservation', {}))) or 'none'}` |"
                )
                for domain, single_row, concurrent_row in zip(BENCHMARK_DOMAINS, single_batch.get("results", []), concurrent_batch.get("results", []))
            ]
        ) + "\n",
    )
    save_markdown(
        out_root / "release_gate.md",
        render_release_gate_markdown(
            release_rows,
            verdict,
            [
                f"{row['domain']}: {', '.join(row.get('failures', []))}"
                for row in failures
            ],
        ),
    )
    save_markdown(out_root / "registry_truth.md", render_registry_truth_markdown(registry_rows))


if __name__ == "__main__":
    asyncio.run(_main())
