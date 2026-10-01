#!/usr/bin/env python3
"""Regenerate ``src/taintrace/data/java_packages.txt`` from Maven Central.

Issue #77 was caused by ``KnownPackagesDB`` having no ``java`` ecosystem, so a
Java dependency was compared against an empty set and could never be escalated.
This script fetches real Maven Central coordinates -- no hand-written guesses --
so the curated data file can be refreshed on demand and audited against a
citable public source.

Usage::

    python scripts/generate_java_packages.py            # regenerate the file
    python scripts/generate_java_packages.py --check    # offline validation (CI)
    python scripts/generate_java_packages.py --verify   # live re-query + diff

``--check`` never touches the network: it validates that the committed file is
sorted, deduplicated, well formed and carries its provenance header. That is
what the test suite runs. ``--verify`` re-queries Maven Central and reports
coordinates that are missing from, or stale in, the committed file.

Primary source
    ``https://repo1.maven.org/maven2/<group>/<path>/`` -- Maven Central's public
    repository index. One directory listing per groupId, no pagination.

Secondary source (cross-check only, via ``--cross-check``)
    ``https://search.maven.org/solrsearch/select``, also served by
    ``https://central.sonatype.com/solrsearch/select``.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = REPO_ROOT / "src" / "taintrace" / "data" / "java_packages.txt"

# Primary source: Maven Central's public repository index.
REPO_INDEX_URL = "https://repo1.maven.org/maven2"
# Cross-check sources: the Maven Central Solr search index.
SEARCH_URL = "https://search.maven.org/solrsearch/select"
ALT_SEARCH_URL = "https://central.sonatype.com/solrsearch/select"
PAGE_SIZE = 200
USER_AGENT = "taintrace-data-generator/1.0 (+https://github.com/yunaremaia/taintrace)"
# Maven Central rate-limits bursts (HTTP 429); pace politely and back off.
REQUEST_DELAY_SECONDS = 0.4
MAX_RETRIES = 5

# Curated groupIds. The *selection* of groups is editorial; every coordinate
# written to the data file is listed by Maven Central, so a typosquatted or
# non-existent artifact can never sneak in here. Groups cover the frameworks,
# libraries, logging, testing, persistence and build tooling that appear in
# almost every Java/Gradle/Maven project.
GROUP_IDS: tuple[str, ...] = (
    # Core utility / collections
    "com.google.guava",
    "com.google.code.findbugs",
    "com.google.errorprone",
    "com.google.j2objc",
    "org.checkerframework",
    "commons-io",
    "commons-codec",
    "commons-beanutils",
    "commons-collections",
    "commons-configuration",
    "commons-dbcp",
    "commons-pool",
    "commons-fileupload",
    "commons-lang",
    "commons-math",
    "commons-net",
    "commons-cli",
    # Apache Commons
    "org.apache.commons",
    # Spring
    "org.springframework",
    "org.springframework.boot",
    "org.springframework.data",
    "org.springframework.security",
    "org.springframework.cloud",
    "org.springframework.session",
    "org.springframework.retry",
    "org.springframework.amqp",
    "org.springframework.kafka",
    "org.springframework.batch",
    "org.springframework.integration",
    "org.springframework.hateoas",
    # Jakarta / JCP
    "jakarta.servlet",
    "jakarta.persistence",
    "jakarta.validation",
    "jakarta.annotation",
    "jakarta.transaction",
    "jakarta.inject",
    "jakarta.json",
    "jakarta.activation",
    "jakarta.mail",
    "jakarta.xml.bind",
    "jakarta.websocket",
    "jakarta.nosql",
    "jakarta.cdi",
    "jakarta.interceptor",
    "jakarta.el",
    "jakarta.faces",
    "jakarta.batch",
    "jakarta.security",
    "jakarta.data",
    "jakarta.enterprise",
    # Logging
    "org.slf4j",
    "ch.qos.logback",
    "log4j",
    "org.apache.logging.log4j",
    # Networking / serialization
    "io.netty",
    "com.fasterxml.jackson.core",
    "com.fasterxml.jackson.datatype",
    "com.fasterxml.jackson.dataformat",
    "com.fasterxml.jackson.module",
    "com.fasterxml.jackson.jaxrs",
    "com.google.code.gson",
    "com.google.protobuf",
    "org.apache.httpcomponents.client5",
    "org.apache.httpcomponents.core5",
    "org.eclipse.jetty",
    "org.eclipse.jetty.websocket",
    "io.undertow",
    "com.squareup.okhttp3",
    "com.squareup.okio",
    "com.squareup.retrofit2",
    "io.grpc",
    # Testing
    "junit",
    "org.junit.jupiter",
    "org.junit.platform",
    "org.junit.vintage",
    "org.mockito",
    "org.mockito.kotlin",
    "org.assertj",
    "org.hamcrest",
    "org.testcontainers",
    "io.rest-assured",
    "org.robolectric",
    "net.bytebuddy",
    "org.objenesis",
    "org.apiguardian",
    "org.opentest4j",
    "org.xmlunit",
    # Persistence / data access
    "org.hibernate",
    "org.hibernate.orm",
    "org.hibernate.validator",
    "org.mybatis",
    "org.mybatis.spring.boot",
    "io.mybatis",
    "org.mongodb",
    "com.mongodb",
    "org.flywaydb",
    "org.liquibase",
    "com.zaxxer",
    "org.elasticsearch",
    "org.elasticsearch.client",
    "com.datastax.oss",
    "org.apache.cassandra",
    "org.apache.kafka",
    "org.apache.zookeeper",
    "org.apache.curator",
    "io.minio",
    "software.amazon.awssdk",
    "com.azure",
    "com.google.cloud",
    # JVM languages / build
    "org.jetbrains.kotlin",
    "org.jetbrains.kotlinx",
    "org.jetbrains",
    "org.projectlombok",
    "com.google.inject",
    "javax.inject",
    "org.apache.maven",
    "org.apache.maven.plugins",
    "org.apache.maven.surefire",
    "org.codehaus.mojo",
    "org.codehaus.plexus",
    "com.google.googlejavaformat",
    "com.google.auto",
    "org.glassfish",
    "com.fasterxml.jackson",
    "org.jetbrains.intellij.deps",
)

HEADER_TEMPLATE = """\
# Maven Central known-package coordinates for the java ecosystem.
#
# Source: Maven Central public repository index ({repo_url}/<group>/<path>/),
#         cross-checkable against the Maven Central search API ({search_url},
#         also served by {alt_url}).
# Selection: the {group_count} groupIds in scripts/generate_java_packages.py
#         (GROUP_IDS) -- frameworks, libraries, logging, testing, persistence
#         and build tooling common to Java projects. Each line below is a
#         `groupId:artifactId` coordinate published by Maven Central; no entry is
#         hand-written. Regenerate with:
#             python scripts/generate_java_packages.py
#         Verify against the live registry with:
#             python scripts/generate_java_packages.py --verify
#
# Generated: {generated}
# Coordinates: {count}
# Note: an artifactId is unique within a group but not across groups, so a bare
#       artifactId is resolved against every group listed here.
"""


def _get(url: str, what: str, accept: str = "text/html") -> str:
    """GET a document, retrying with exponential backoff on 429/5xx."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    for attempt in range(MAX_RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or 500 <= exc.code < 600
            if not retryable or attempt == MAX_RETRIES - 1:
                raise SystemExit(
                    f"Maven Central rejected request for {what!r}: HTTP {exc.code}") from exc
            delay = REQUEST_DELAY_SECONDS * (2 ** attempt)
            print(f"  HTTP {exc.code} for {what}; retrying in {delay:.1f}s", file=sys.stderr)
        except urllib.error.URLError as exc:
            if attempt == MAX_RETRIES - 1:
                raise SystemExit(f"cannot reach Maven Central ({url}): {exc.reason}") from exc
            delay = REQUEST_DELAY_SECONDS * (2 ** attempt)
            print(f"  {exc.reason}; retrying in {delay:.1f}s", file=sys.stderr)
        time.sleep(delay)
    raise SystemExit(f"exhausted retries querying Maven Central for {what!r}")


def fetch_group(group_id: str) -> list[str]:
    """Return every ``groupId:artifactId`` listed under ``group_id``.

    Reads the group directory in Maven Central's repository index. Only
    directory links are artifact directories -- files (``maven-metadata.xml``)
    and parent links (``../``) are ignored. Note that plenty of legitimate
    artifactIds contain dots (``jakarta.transaction-api``), so the trailing
    slash is what distinguishes a directory from a file.
    """
    path = group_id.replace(".", "/")
    body = _get(f"{REPO_INDEX_URL}/{path}/", group_id)
    artifacts = []
    for href in re.findall(r'href="([^"]+)"', body):
        if not href.endswith("/") or href.startswith(("?", "#", "/")):
            continue
        name = html.unescape(href)[:-1]
        if not name or name == "..":
            continue
        artifacts.append(f"{group_id}:{name}")
    time.sleep(REQUEST_DELAY_SECONDS)
    return sorted(artifacts)


def fetch_group_via_search(group_id: str, url: str = SEARCH_URL) -> list[str]:
    """Return a group's coordinates from the Solr search index (cross-check)."""
    coordinates: list[str] = []
    start = 0
    while True:
        query = urllib.parse.urlencode({
            "q": f'g:"{group_id}"', "core": "gav", "rows": PAGE_SIZE,
            "start": start, "wt": "json",
        })
        payload = json.loads(_get(f"{url}?{query}", group_id, accept="application/json"))
        response = payload.get("response", {})
        docs = response.get("docs", [])
        for doc in docs:
            group, artifact = doc.get("g", ""), doc.get("a", "")
            if group and artifact:
                coordinates.append(f"{group}:{artifact}")
        start += len(docs)
        if not docs or start >= response.get("numFound", 0):
            break
        time.sleep(REQUEST_DELAY_SECONDS)
    time.sleep(REQUEST_DELAY_SECONDS)
    return sorted(coordinates)


def collect(url: str = SEARCH_URL, cross_check: bool = False, verbose: bool = True) -> list[str]:
    """Fetch every curated group and return sorted, deduplicated coordinates."""
    coordinates: set[str] = set()
    empty_groups: list[str] = []
    for group_id in GROUP_IDS:
        found = fetch_group(group_id)
        if not found:
            empty_groups.append(group_id)
        coordinates.update(found)
        if verbose:
            note = ""
            if cross_check:
                delta = len(set(found) ^ set(fetch_group_via_search(group_id, url=url)))
                note = " [search index agrees]" if delta == 0 else f" [search index differs by {delta}]"
            print(f"  {group_id:<45} {len(found):>4} artifacts{note}", file=sys.stderr)
    if empty_groups:
        # A group listing nothing is usually a typo in GROUP_IDS or a group that
        # was renamed. Fail loudly rather than silently shipping less coverage.
        raise SystemExit("no artifacts published for groupIds: " + ", ".join(empty_groups))
    return sorted(coordinates)


def render(coordinates: list[str], generated: str) -> str:
    header = HEADER_TEMPLATE.format(
        repo_url=REPO_INDEX_URL,
        search_url=SEARCH_URL,
        alt_url=ALT_SEARCH_URL,
        group_count=len(GROUP_IDS),
        generated=generated,
        count=len(coordinates),
    )
    return header + "\n".join(coordinates) + "\n"


def validate(text: str) -> list[str]:
    """Validate a data file's structure; return a list of problems."""
    problems: list[str] = []
    lines = text.splitlines()
    body = [line for line in lines if line.strip() and not line.startswith("#")]
    header = "\n".join(line for line in lines if line.startswith("#"))

    if not body:
        return ["data file contains no coordinates"]
    if REPO_INDEX_URL not in header:
        problems.append("header does not name the Maven Central source")
    if "Generated:" not in header:
        problems.append("header has no generation timestamp")
    if "scripts/generate_java_packages.py" not in header:
        problems.append("header does not name the regeneration script")
    for coordinate in body:
        if coordinate != coordinate.strip():
            problems.append(f"whitespace in entry {coordinate!r}")
        if coordinate.count(":") != 1 or not all(coordinate.split(":")):
            problems.append(f"not a group:artifact coordinate: {coordinate!r}")
    if body != sorted(body):
        problems.append("entries are not sorted")
    if len(body) != len(set(body)):
        problems.append("entries contain duplicates")
    return problems


def entries(text: str) -> list[str]:
    """Return the coordinate lines of a data file, comments excluded."""
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.startswith("#")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="validate the committed data file offline (no network)")
    parser.add_argument("--verify", action="store_true",
                        help="re-query Maven Central and diff against the committed file")
    parser.add_argument("--cross-check", action="store_true",
                        help="during --verify, also query the Solr search index")
    parser.add_argument("--url", default=SEARCH_URL,
                        help="search API endpoint used by --cross-check")
    parser.add_argument("--output", type=Path, default=DATA_FILE,
                        help="data file to write")
    args = parser.parse_args(argv)

    if args.check and not args.verify:
        committed = args.output.read_text(encoding="utf-8")
        problems = validate(committed)
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            return 1
        print(f"ok: {args.output.relative_to(REPO_ROOT)} "
              f"({len(entries(committed))} coordinates, provenance present)")
        return 0

    print(f"Fetching {len(GROUP_IDS)} groupIds from {REPO_INDEX_URL}...", file=sys.stderr)
    coordinates = collect(url=args.url, cross_check=args.cross_check)
    generated = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rendered = render(coordinates, generated)

    problems = validate(rendered)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    if args.verify:
        committed = args.output.read_text(encoding="utf-8")
        if rendered == committed:
            print(f"ok: committed data matches Maven Central ({len(coordinates)} coordinates)")
            return 0
        committed_entries = set(entries(committed))
        live_entries = set(coordinates)
        print("error: committed data differs from Maven Central", file=sys.stderr)
        for coordinate in sorted(live_entries - committed_entries)[:20]:
            print(f"  published but missing from data file: {coordinate}", file=sys.stderr)
        for coordinate in sorted(committed_entries - live_entries)[:20]:
            print(f"  in data file but no longer listed:   {coordinate}", file=sys.stderr)
        print(f"  ({len(live_entries - committed_entries)} missing, "
              f"{len(committed_entries - live_entries)} stale)", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(f"wrote {len(coordinates)} coordinates to {args.output.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())