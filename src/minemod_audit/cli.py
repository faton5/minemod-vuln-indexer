import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer

from minemod_audit.config import load_settings
from minemod_audit.pipeline import Pipeline

app = typer.Typer(no_args_is_help=True)
providers_app = typer.Typer(no_args_is_help=True)
app.add_typer(providers_app, name="providers")


DatabaseOption = Annotated[Path | None, typer.Option("--database")]
OutputOption = Annotated[Path | None, typer.Option("--output-directory")]
ResumeOption = Annotated[bool, typer.Option("--resume")]
RefreshOption = Annotated[bool, typer.Option("--refresh")]
OfflineOption = Annotated[bool, typer.Option("--offline")]
VerboseOption = Annotated[bool, typer.Option("--verbose")]


def _pipeline(
    database: Path | None,
    output_directory: Path | None,
    offline: bool,
    refresh: bool,
    verbose: bool,
) -> Pipeline:
    settings = load_settings(database=database, output_directory=output_directory, verbose=verbose)
    return Pipeline(settings, offline=offline, refresh=refresh)


@app.command("collect-mods")
def collect_mods(
    limit: Annotated[int, typer.Option("--limit", min=1)] = 20,
    provider: Annotated[str, typer.Option("--provider")] = "modrinth",
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    mods = pipeline.collect_mods(limit=limit, provider=provider)
    typer.echo(f"Collected {len(mods)} mods")


@app.command("dashboard")
def dashboard(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8501,
    database: Annotated[Path, typer.Option("--database")] = Path("data/minemod.sqlite"),
    open_browser: Annotated[bool, typer.Option("--open-browser")] = False,
    debug: Annotated[bool, typer.Option("--debug")] = False,
) -> None:
    env = os.environ.copy()
    env["MINEMOD_DASHBOARD_DATABASE"] = str(database)
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "dashboard/app.py",
        "--server.address",
        host,
        "--server.port",
        str(port),
        "--server.headless",
        "false" if open_browser else "true",
        "--browser.gatherUsageStats",
        "false",
    ]
    if debug:
        typer.echo("Launching Streamlit dashboard in debug mode")
    subprocess.run(command, check=True, env=env)


@app.command("collect-modpacks")
def collect_modpacks(
    limit: Annotated[int, typer.Option("--limit", min=1)] = 100,
    provider: Annotated[str, typer.Option("--provider")] = "modrinth",
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    modpacks = pipeline.collect_modpacks(limit=limit, provider=provider)
    typer.echo(f"Collected {len(modpacks)} modpacks")


@providers_app.command("status")
def providers_status(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    typer.echo(f"{'Provider':<12} {'Status':<10} {'Priority':<8} Reason")
    for status in pipeline.provider_status():
        priority = "-" if status.priority is None else str(status.priority)
        typer.echo(f"{status.name:<12} {status.status:<10} {priority:<8} {status.reason}")


@app.command("resolve-repositories")
def resolve_repositories(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    repositories = pipeline.resolve_repositories()
    typer.echo(f"Resolved {sum(1 for item in repositories if item.repository)} repositories")


@app.command("collect-advisories")
def collect_advisories(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    vulnerabilities = pipeline.collect_advisories()
    typer.echo(f"Collected {len(vulnerabilities)} vulnerability signals")


@app.command("prioritize-mods")
def prioritize_mods(
    top: Annotated[int, typer.Option("--top", min=1)] = 10,
    provider: Annotated[str, typer.Option("--provider")] = "modrinth",
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    prioritized = pipeline.prioritize_mods(top=top, provider=provider)
    typer.echo(f"Prioritized {len(prioritized)} mods")


@app.command("mine-security-signals")
def mine_security_signals(
    top: Annotated[int, typer.Option("--top", min=1)] = 10,
    per_term: Annotated[int, typer.Option("--per-term", min=1, max=20)] = 5,
    lookback_days: Annotated[int, typer.Option("--lookback-days", min=1)] = 180,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    vulnerabilities = pipeline.discover_recent_fixes(
        top=top,
        lookback_days=lookback_days,
        per_term=per_term,
    )
    typer.echo(f"Mined {len(vulnerabilities)} candidate security signals")


@app.command("discover-recent-fixes")
def discover_recent_fixes(
    top: Annotated[int, typer.Option("--top", min=1)] = 20,
    lookback_days: Annotated[int, typer.Option("--lookback-days", min=1)] = 180,
    per_term: Annotated[int, typer.Option("--per-term", min=1, max=20)] = 5,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    bundles = pipeline.discover_recent_fixes(
        top=top,
        lookback_days=lookback_days,
        per_term=per_term,
    )
    typer.echo(f"Discovered {len(bundles)} recent fix evidence bundles")


@app.command("correlate-recent-fixes")
def correlate_recent_fixes(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume, refresh
    pipeline = _pipeline(database, output_directory, offline, False, verbose)
    findings = pipeline.correlate_recent_fixes()
    typer.echo(f"Produced {len(findings)} recent-fix findings")


@app.command("index-modpacks")
def index_modpacks(
    limit: Annotated[int, typer.Option("--limit", min=1)] = 500,
    releases_per_pack: Annotated[int, typer.Option("--releases-per-pack", min=1)] = 5,
    minecraft_version: Annotated[str | None, typer.Option("--minecraft-version")] = None,
    loader: Annotated[str | None, typer.Option("--loader")] = None,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    modpacks, releases, components = pipeline.index_modpacks(
        limit=limit,
        releases_per_pack=releases_per_pack,
        minecraft_version=minecraft_version,
        loader=loader,
    )
    typer.echo(
        f"Indexed {len(modpacks)} modpacks, {len(releases)} releases, {len(components)} components"
    )


@app.command("index-curseforge-packs")
def index_curseforge_packs(
    limit: Annotated[int, typer.Option("--limit", min=1)] = 200,
    releases: Annotated[int, typer.Option("--releases", min=1)] = 3,
    minecraft_version: Annotated[str | None, typer.Option("--minecraft-version")] = None,
    loader: Annotated[str | None, typer.Option("--loader")] = None,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    modpacks, indexed_releases, components = pipeline.index_curseforge_modpacks(
        limit=limit,
        releases_per_pack=releases,
        minecraft_version=minecraft_version,
        loader=loader,
    )
    typer.echo(
        f"Indexed {len(modpacks)} CurseForge packs, "
        f"{len(indexed_releases)} releases, {len(components)} components"
    )


@app.command("build-canonical-mods")
def build_canonical_mods(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume, refresh
    pipeline = _pipeline(database, output_directory, offline, False, verbose)
    canonicals = pipeline.build_canonical_mods()
    typer.echo(f"Built {len(canonicals)} canonical mods")


@app.command("analyze-release-diffs")
def analyze_release_diffs(
    top_libraries: Annotated[int, typer.Option("--top-libraries", min=1)] = 50,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    candidates = pipeline.analyze_release_diffs(top_libraries=top_libraries)
    typer.echo(f"Analyzed release diffs and produced {len(candidates)} candidates")


@app.command("hunt-release-lag")
def hunt_release_lag(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume, refresh
    pipeline = _pipeline(database, output_directory, offline, False, verbose)
    findings = pipeline.hunt_release_lag()
    typer.echo(f"Produced {len(findings)} release lag findings")


@app.command("hunt-recent-security-fixes")
def hunt_recent_security_fixes(
    provider: Annotated[str, typer.Option("--provider")] = "all",
    updated_within_days: Annotated[int, typer.Option("--updated-within-days", min=1)] = 14,
    popular_mods: Annotated[int, typer.Option("--popular-mods", min=1)] = 100,
    popular_modpacks: Annotated[int, typer.Option("--popular-modpacks", min=1)] = 200,
    top: Annotated[int, typer.Option("--top", min=1)] = 20,
    ai: Annotated[bool, typer.Option("--ai/--no-ai")] = False,
    ai_model: Annotated[str | None, typer.Option("--ai-model")] = None,
    ai_review_model: Annotated[str | None, typer.Option("--ai-review-model")] = None,
    ai_max_candidates: Annotated[int | None, typer.Option("--ai-max-candidates", min=1)] = None,
    ai_max_review_calls: Annotated[
        int | None,
        typer.Option("--ai-max-review-calls", min=0),
    ] = None,
    ai_refresh: Annotated[bool, typer.Option("--ai-refresh")] = False,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    requested = {item.strip().lower() for item in provider.split(",") if item.strip()}
    if provider.strip().lower() == "all":
        requested = {"modrinth", "curseforge"}
    if "curseforge" in requested:
        try:
            curseforge = pipeline.verify_curseforge_connection()
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"CurseForge: error - {exc.__class__.__name__}", err=True)
            raise typer.Exit(1) from exc
        if curseforge.status != "enabled":
            reason = curseforge.reason
            typer.echo(f"CurseForge: error - {reason}", err=True)
            raise typer.Exit(1)
        typer.echo("CurseForge: enabled")
    if ai_refresh:
        typer.echo("Gemini: warning - AI cache will be ignored for this run", err=True)
    candidates = pipeline.hunt_recent_security_fixes(
        provider=provider,
        updated_within_days=updated_within_days,
        popular_mods=popular_mods,
        popular_modpacks=popular_modpacks,
        top=top,
        ai=ai,
        ai_model=ai_model,
        ai_review_model=ai_review_model,
        ai_max_candidates=ai_max_candidates,
        ai_max_review_calls=ai_max_review_calls,
        ai_refresh=ai_refresh,
    )
    pipeline.report()
    typer.echo(f"Produced {len(candidates)} recent security fix candidates")


@app.command("analyze-candidates-with-gemini")
def analyze_candidates_with_gemini(
    max_candidates: Annotated[int, typer.Option("--max-candidates", min=1)] = 20,
    max_review_calls: Annotated[int, typer.Option("--max-review-calls", min=0)] = 3,
    ai_model: Annotated[str | None, typer.Option("--ai-model")] = None,
    ai_review_model: Annotated[str | None, typer.Option("--ai-review-model")] = None,
    ai_refresh: Annotated[bool, typer.Option("--ai-refresh")] = False,
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    if ai_refresh:
        typer.echo("Gemini: warning - AI cache will be ignored for this run", err=True)
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    candidates = pipeline.analyze_candidates_with_gemini(
        max_candidates=max_candidates,
        max_review_calls=max_review_calls,
        ai_model=ai_model,
        ai_review_model=ai_review_model,
        ai_refresh=ai_refresh,
    )
    analyzed = sum(1 for candidate in candidates if candidate.ai_verdict)
    cache_hits = sum(1 for candidate in candidates if candidate.ai_cache_hit)
    typer.echo(
        "Gemini analysis complete: "
        f"{analyzed}/{len(candidates)} candidates annotated, {cache_hits} cache hits"
    )


@app.command("inspect-fix")
def inspect_fix(
    candidate_id: Annotated[str, typer.Option("--candidate-id")],
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume, refresh
    pipeline = _pipeline(database, output_directory, offline, False, verbose)
    candidate = pipeline.inspect_fix(candidate_id=candidate_id)
    if candidate is None:
        typer.echo(f"Candidate not found: {candidate_id}", err=True)
        raise typer.Exit(1)
    typer.echo(json.dumps(candidate.model_dump(mode="json"), indent=2, ensure_ascii=False))


@app.command("correlate")
def correlate(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume, refresh
    pipeline = _pipeline(database, output_directory, offline, False, verbose)
    findings = pipeline.correlate()
    typer.echo(f"Produced {len(findings)} findings")


@app.command("report")
def report(
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume, refresh
    pipeline = _pipeline(database, output_directory, offline, False, verbose)
    pipeline.report()
    typer.echo("Reports written")


@app.command("run")
def run_all(
    limit_mods: Annotated[int, typer.Option("--limit-mods", min=1)] = 20,
    limit_modpacks: Annotated[int, typer.Option("--limit-modpacks", min=1)] = 500,
    releases_per_pack: Annotated[int, typer.Option("--releases-per-pack", min=1)] = 5,
    minecraft_version: Annotated[str | None, typer.Option("--minecraft-version")] = None,
    loader: Annotated[str | None, typer.Option("--loader")] = None,
    providers: Annotated[str, typer.Option("--providers")] = "modrinth",
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    pipeline.collect_mods(limit=limit_mods, provider=providers)
    pipeline.resolve_repositories()
    pipeline.collect_advisories()
    if providers == "curseforge":
        pipeline.index_modpacks(
            limit=limit_modpacks,
            releases_per_pack=releases_per_pack,
            minecraft_version=minecraft_version,
            loader=loader,
        )
    else:
        pipeline.collect_modpacks(limit=limit_modpacks, provider=providers)
    pipeline.correlate()
    pipeline.report()
    typer.echo("Run complete")


@app.command("targeted-run")
def targeted_run(
    limit_modpacks: Annotated[int, typer.Option("--limit-modpacks", min=1)] = 20,
    top: Annotated[int, typer.Option("--top", min=1)] = 10,
    per_term: Annotated[int, typer.Option("--per-term", min=1, max=20)] = 5,
    lookback_days: Annotated[int, typer.Option("--lookback-days", min=1)] = 180,
    providers: Annotated[str, typer.Option("--providers")] = "modrinth",
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    pipeline.collect_modpacks(limit=limit_modpacks, provider=providers)
    prioritized = pipeline.prioritize_mods(top=top, provider=providers)
    bundles = pipeline.discover_recent_fixes(
        top=top,
        lookback_days=lookback_days,
        per_term=per_term,
    )
    pipeline.correlate()
    pipeline.report()
    typer.echo(
        f"Targeted run complete: {len(prioritized)} prioritized mods, "
        f"{len(bundles)} recent fix evidence bundles"
    )


if __name__ == "__main__":
    app()
