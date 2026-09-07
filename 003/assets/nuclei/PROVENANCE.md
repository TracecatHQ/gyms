# Nuclei template provenance

`CVE-2026-21858.yaml` is vendored from the official
`projectdiscovery/nuclei-templates` repository at revision
`b78b60c84a754c0ce2a8b9f0710edc8987adeb85`, committed 2026-08-29T10:07:28Z.
That revision is more than seven days old on the gym implementation date of
2026-09-06 and follows the 2026-08-14 upstream fix
`b07893e75279f40c1c3ac81016ff5bc647181830`, which added the
`/rest/sentry.js` fallback required to detect n8n 1.65.0 through 1.111.x.

Official source:
<https://github.com/projectdiscovery/nuclei-templates/blob/b78b60c84a754c0ce2a8b9f0710edc8987adeb85/http/cves/2026/CVE-2026-21858.yaml>

The embedded ProjectDiscovery signature line is retained; the vendored file adds
a final POSIX newline. The upstream raw SHA-256 is
`e282efc503e9bc440180966d0d29aacb8d716d399b2a8fc22bcc22c601bcc613` and the
newline-terminated vendored SHA-256 is
`c4240eec698f1cf9bbc6739f944afe4ef49f30f95227142ec744f555a566c28f`.
The asset is a detection
template: it fingerprints a vulnerable version and does not actively reproduce
the issue.
