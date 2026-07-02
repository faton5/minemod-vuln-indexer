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
