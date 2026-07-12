/* 在 Material 顶栏右上角（紧邻 GitHub 仓库链接）注入一个 Wiki 跳转按钮，新标签打开。 */
(function () {
  function inject() {
    var inner = document.querySelector(".md-header__inner");
    if (!inner || inner.querySelector(".kh-wiki-btn")) return;

    var a = document.createElement("a");
    a.href = "https://github.com/x500x/wknet/wiki";
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.className = "kh-wiki-btn";
    a.title = "在新标签打开项目 Wiki";
    a.innerHTML =
      '<svg class="kh-wiki-btn__icon" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">' +
      '<path fill="currentColor" d="M18 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zm0 18H8V4h10v16zM6 4v16H6V4z"/>' +
      '<path fill="currentColor" d="M10 6h6v2h-6zm0 4h6v2h-6zm0 4h4v2h-4z"/></svg>' +
      '<span class="kh-wiki-btn__label">Wiki</span>';

    var source = inner.querySelector(".md-header__source");
    if (source) inner.insertBefore(a, source);
    else inner.appendChild(a);
  }

  if (document.readyState !== "loading") inject();
  else document.addEventListener("DOMContentLoaded", inject);

  // 兼容 Material 的即时导航（instant loading）
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(inject);
  }
})();
