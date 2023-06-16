Note that dependencies version bumps PRs will not be merged. Downstream projects manage their
dependencies by themselves, what we do here doesn't matter. See
https://github.com/miekg/dns/pull/1049#issuecomment-565718842 and
https://github.com/golang/go/issues/35798#issuecomment-558358674 for more context.

If your PR introduces backward incompatible changes it will very likely not be merged.

We support the last two major Go versions, if your PRs uses features from a too new Go version, it
will not be merged.
