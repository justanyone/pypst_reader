"""Hatchling build hook: drop the force-included `.gitignore` from the sdist.

Ported from: nothing — this is packaging glue, not part of the read path.

hatchling.builders.sdist.SdistBuilder.get_default_build_data() unconditionally
force-includes two files that have nothing to do with the published package:
the nearest `.gitignore` (found by walking up from the project root, for build
reproducibility), and this script itself, `hatch_build.py` (`DEFAULT_BUILD_
SCRIPT`, so a wheel built later from the sdist can still run it). There is no
include/exclude config key that suppresses a *forced* include —
`[tool.hatch.build.targets.sdist].exclude` only filters the normal
project-file walk — so the sdist's explicit allow-list in pyproject.toml
(src/pypstreader, docs/adr, README, LICENSE, NOTICE, pyproject.toml) would
otherwise gain two stray files at the archive root. This hook runs after
hatchling builds its default `force_include` map and before the archive is
written, and removes both entries. Dropping `hatch_build.py` itself is safe
here: it is registered only under `[tool.hatch.build.targets.sdist.hooks.
custom]`, so pip building a *wheel* from the unpacked sdist never looks for
it — only rebuilding the sdist itself would, and that happens from this
working tree, not from an unpacked sdist. Scoped to the sdist target only
(see [tool.hatch.build.targets.sdist.hooks.custom] below); the wheel target
force-includes neither file in the first place, so it needs no equivalent
hook.
"""

from __future__ import annotations

from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_DROP_TARGETS = {".gitignore", "hatch_build.py"}


class DropPackagingOnlyFilesHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        force_include = build_data.get("force_include", {})
        for source, target in list(force_include.items()):
            if target in _DROP_TARGETS:
                del force_include[source]
