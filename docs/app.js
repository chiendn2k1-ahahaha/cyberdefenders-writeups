(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("labdata").textContent);
  var root = document.getElementById("labapp");
  root.textContent = "";
  var DIFF = ["insane", "hard", "medium", "easy"];
  var DIFF_VI = { insane: "Insane", hard: "Hard", medium: "Medium", easy: "Easy" };

  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") e.textContent = attrs[k];
      else if (k === "cls") e.className = attrs[k];
      else e.setAttribute(k, attrs[k]);
    });
    (kids || []).forEach(function (c) { if (c) e.appendChild(c); });
    return e;
  }
  function uniq(key) {
    var s = {};
    data.forEach(function (r) { [].concat(r[key]).forEach(function (v) { if (v) s[v] = (s[v] || 0) + 1; }); });
    return Object.keys(s).sort();
  }
  function select(id, label, values, fmt) {
    var s = el("select", { id: id, "aria-label": label });
    s.appendChild(el("option", { value: "", text: label + ": tất cả" }));
    values.forEach(function (v) { s.appendChild(el("option", { value: v, text: fmt ? fmt(v) : v })); });
    return s;
  }

  var q = el("input", { type: "search", id: "q", placeholder: "Tìm theo tên lab, công cụ, tactic...", "aria-label": "Tìm kiếm" });
  var fCat = select("fcat", "Nhóm", uniq("categories"));
  var fDiff = select("fdiff", "Độ khó", DIFF, function (v) { return DIFF_VI[v]; });
  var fTac = select("ftac", "Tactic", uniq("tactics"));
  var fTool = select("ftool", "Công cụ", uniq("tools"));
  var fW = el("input", { type: "checkbox", id: "fw" });
  var nW = data.filter(function (r) { return r.writeup; }).length;
  if (nW > 0) fW.checked = true;
  var wLabel = el("label", { cls: "chk", "for": "fw" }, [fW, document.createTextNode(" Chỉ bài có writeup (" + nW + ")")]);
  var reset = el("button", { type: "button", cls: "reset", text: "Xóa lọc" });
  var count = el("p", { cls: "count" });
  var grid = el("div", { cls: "grid" });
  root.appendChild(el("div", { cls: "filters" }, [q, fCat, fDiff, fTac, fTool, wLabel, reset]));
  root.appendChild(count);
  root.appendChild(grid);

  function card(r) {
    var href = r.writeup || ("https://cyberdefenders.org/blueteam-ctf-challenges/" + r.slug + "/");
    var a = el("a", { cls: "card" + (r.writeup ? " has" : ""), href: href });
    if (!r.writeup) { a.setAttribute("target", "_blank"); a.setAttribute("rel", "noopener noreferrer"); }
    var head = el("div", { cls: "chead" }, [
      el("span", { cls: "diff d-" + r.difficulty, text: DIFF_VI[r.difficulty] || r.difficulty }),
      el("span", { cls: "cat", text: r.categories.join(", ") })
    ]);
    a.appendChild(head);
    a.appendChild(el("h3", { text: r.name }));
    a.appendChild(el("p", { cls: "obj", text: r.summary || r.objective }));
    var tags = el("div", { cls: "tags" });
    r.tactics.slice(0, 4).forEach(function (t) { tags.appendChild(el("span", { cls: "tag", text: t })); });
    a.appendChild(tags);
    a.appendChild(el("div", { cls: "cfoot" }, [
      el("span", { text: r.questions + " câu hỏi" }),
      el("span", { cls: r.writeup ? "go" : "muted", text: r.writeup ? "Đọc writeup" : "Chưa có writeup" })
    ]));
    return a;
  }

  function norm(s) { return (s || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/đ/g, "d"); }
  function render() {
    var t = norm(q.value.trim());
    var rows = data.filter(function (r) {
      if (fW.checked && !r.writeup) return false;
      if (fCat.value && r.categories.indexOf(fCat.value) < 0) return false;
      if (fDiff.value && r.difficulty !== fDiff.value) return false;
      if (fTac.value && r.tactics.indexOf(fTac.value) < 0) return false;
      if (fTool.value && r.tools.indexOf(fTool.value) < 0) return false;
      if (t) {
        var hay = norm([r.name, r.slug, r.objective, r.summary, r.categories.join(" "), r.tactics.join(" "), r.tools.join(" ")].join(" "));
        if (hay.indexOf(t) < 0) return false;
      }
      return true;
    });
    grid.textContent = "";
    rows.forEach(function (r) { grid.appendChild(card(r)); });
    count.textContent = rows.length + " / " + data.length + " lab";
    if (!rows.length) grid.appendChild(el("p", { cls: "muted", text: fW.checked ? "Chưa có writeup khớp bộ lọc. Bỏ chọn \"Chỉ bài có writeup\" để xem toàn bộ lab." : "Không có lab khớp bộ lọc." }));
  }
  [q, fCat, fDiff, fTac, fTool, fW].forEach(function (e) { e.addEventListener("input", render); e.addEventListener("change", render); });
  reset.addEventListener("click", function () { q.value = ""; [fCat, fDiff, fTac, fTool].forEach(function (s) { s.value = ""; }); fW.checked = false; render(); });
  render();
})();
