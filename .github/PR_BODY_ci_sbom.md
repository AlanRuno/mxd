ci: SBOM generation in docker-build + tag-gated GHCR publish and cosign signing

Summary
- Adds CycloneDX SBOM generation for:
  - Source tree (sbom-source.cdx.json)
  - Docker image built in PR (sbom-image.cdx.json)
- Uploads SBOMs as PR artifacts
- Adds docker-publish-sign job (tag-gated on refs/tags/*) that:
  - Builds and pushes ghcr.io/${{ github.repository }}:TAG and :latest
  - Installs cosign and performs keyless signing (non-blocking)
  - Generates SBOM for pushed GHCR image and uploads as artifact
- Keeps Trivy security scan as part of CI (non-blocking on PRs to maintain contributor ergonomics)

Behavior
- On PRs: docker-build job runs; SBOMs are generated and attached as artifacts. No image publish/signing occurs.
- On tags: docker-publish-sign job runs (permissions: contents read, packages write, id-token write), pushes to GHCR, attempts signing with cosign (non-blocking), and publishes an SBOM of the pushed image as an artifact.

Notes
- No secrets added; uses GITHUB_TOKEN for GHCR auth on tagged releases.
- Cosign keyless signing uses OIDC; failures are tolerated to avoid blocking releases in repos without configured OIDC trust.
- YAML validated in CI for this PR; security-scan remains non-blocking.

Verification
- Local smoke: docker-build completes; SBOMs created and uploaded.
- CI: On PRs, expect to see:
  - docker-build: pass
  - security-scan: pass
  - SBOM artifacts: sbom-source.cdx.json and sbom-image.cdx.json


