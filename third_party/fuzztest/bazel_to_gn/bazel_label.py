# Copyright 2026 The Pigweed Authors
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
"""Parses Bazel labels and provides helper methods for working with them."""

from pathlib import PurePosixPath
import re

from bazel_errors import ParseError

LABEL_PAT = re.compile(
    r'^(?:(?:@(?P<canonical>@)?(?P<repo>[^/@]*))?//(?P<package>[^:]*))?'
    r'(?::(?P<name>[^:]+))?$'
)

# In canonical labels, Bazel names a module's repo "<module>+" (Bazel 8) or
# "<module>~" (Bazel 7). Extension-generated repos contain further
# marker-separated segments (e.g. "protobuf++protoc+prebuilt_protoc") and
# cannot be mapped back to a module name; they are kept verbatim.
CANONICAL_MODULE_PAT = re.compile(r'^([^+~]+)[+~]$')


class BazelLabel:
    """Represents a Bazel target identifier."""

    def __init__(
        self,
        repo_name: str,
        package: str,
        name: str,
    ) -> None:
        self._repo_name = repo_name
        self._package = package
        self._name = name

    def __str__(self) -> str:
        """Canonical representation of a Bazel label."""
        return f'@{self._repo_name}//{self._package}:{self._name}'

    def repo_name(self) -> str:
        """Returns the repository identifier associated with this label."""
        return self._repo_name

    def package(self) -> str:
        """Returns the package path associated with this label."""
        return self._package

    def name(self) -> str:
        """Returns the target name associated with this label."""
        return self._name

    @classmethod
    def from_string(
        cls,
        label_str: str,
        repo_name: str | None = None,
        package: str | None = None,
    ) -> 'BazelLabel':
        """Creates a Bazel label.

        This method will attempt to parse the repo, package, and target portion
        of the given label string. If the repo portion of the label is omitted,
        it will use the given repo, if provided. If the repo and the package
        portions of the label are omitted, it will use the given package, if
        provided. If the target portion is omitted, the last segment of the
        package will be used.

        For labels of the form "@//pkg:target", the repo name is considered the
        current repo, i.e. the empty string. Similarly, for labels of the form
        "//pkg:target".

        Labels with canonical repo names, i.e. starting with '@@' such as
        '@@foo+//bar:baz', are accepted, and module repo names are normalized
        to their apparent form, e.g. '@@foo+//bar:baz' parses the same as
        '@foo//bar:baz'. Canonical names of extension-generated repos are kept
        verbatim.

        Args:
            label_str: Bazel label string, like "@repo//pkg:target".
            repo: Repo to use if omitted from label, e.g. as in "//pkg:target".
                A repo parsed from the label takes precedence over this
                argument.
            package: Package to use if omitted from label, e.g. as in ":target".
                A package parsed from the label takes precedence over this
                argument.
        """
        match = re.match(LABEL_PAT, label_str)
        # Either invalid label or no label provided.
        if not label_str or not match:
            raise ParseError(f'invalid label: "{label_str}"')

        # Prefer repo/package/target from label string, then from arguments.
        if match.group('repo'):
            repo_name = match.group('repo')
            if match.group('canonical'):
                canonical = CANONICAL_MODULE_PAT.match(repo_name)
                if canonical:
                    repo_name = canonical.group(1)
        # An empty package that was explicitly present in the label, as in
        # "@repo//:target", must not be overridden by the package argument.
        if match.group('package') is not None:
            package = match.group('package')
        name = None
        if match.group('name'):
            name = match.group('name')

        # If the label string is of the form //package[:target], assume the
        # repo name is empty (the current repo).
        if not repo_name and package:
            repo_name = ''

        # If the label string is of the form [@repo]//:target, assume the
        # package name is empty.
        if not package and name:
            package = ''

        # If the label string is of the form //package, assume the target name
        # is the same as the package name.
        if not name and package:
            name = PurePosixPath(package).name

        # Verify that we have parsed a repo, package, and target.
        if repo_name is None:
            raise ParseError(f'unable to determine repo name: "{label_str}"')
        if package is None:
            raise ParseError(f'unable to determine package: "{label_str}"')
        if name is None:
            raise ParseError(f'unable to determine target name: "{label_str}"')
        return cls(repo_name, package, name)
