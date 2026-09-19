(function () {
  const versionLinks = Array.from(document.querySelectorAll(".footer-version"));
  if (!versionLinks.length) return;

  function isSafeExternalUrl(value) {
    const v = String(value || "").trim();
    if (!v) return false;
    return !/^\s*(javascript|data|vbscript|file):/i.test(v);
  }

  fetch("/version.json", { cache: "no-store" })
    .then((res) => res.ok ? res.json() : null)
    .then((payload) => {
      if (!payload || typeof payload !== "object") return;

      const version = typeof payload.version === "string" ? payload.version.trim() : "";
      const link = typeof payload.link === "string" ? payload.link.trim() : "";
      if (!version) return;

      versionLinks.forEach((linkEl) => {
        const valueEl = linkEl.querySelector(".footer-version-value");
        if (valueEl) valueEl.textContent = version;

        if (link && isSafeExternalUrl(link)) {
          linkEl.href = link;
        } else {
          linkEl.removeAttribute("href");
        }

        linkEl.setAttribute("aria-label", "Project version " + version);
      });
    })
    .catch(() => {
      // Leave the placeholder visible if version metadata is unavailable.
    });
})();
