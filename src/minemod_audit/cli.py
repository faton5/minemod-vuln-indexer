from pathlib import Path
from typing import Annotated

import typer

from minemod_audit.config import load_settings
from minemod_audit.pipeline import Pipeline

app = typer.Typer(no_args_is_help=True)


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
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    mods = pipeline.collect_mods(limit=limit)
    typer.echo(f"Collected {len(mods)} mods")


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
    database: DatabaseOption = None,
    output_directory: OutputOption = None,
    resume: ResumeOption = False,
    refresh: RefreshOption = False,
    offline: OfflineOption = False,
    verbose: VerboseOption = False,
) -> None:
    del resume
    pipeline = _pipeline(database, output_directory, offline, refresh, verbose)
    pipeline.collect_mods(limit=limit_mods)
    pipeline.resolve_repositories()
    pipeline.collect_advisories()
    pipeline.index_modpacks(
        limit=limit_modpacks,
        releases_per_pack=releases_per_pack,
        minecraft_version=minecraft_version,
        loader=loader,
    )
    pipeline.correlate()
    pipeline.report()
    typer.echo("Run complete")


if __name__ == "__main__":
    app()
