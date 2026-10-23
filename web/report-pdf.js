/* Arztbericht als echtes PDF (funktioniert auch in der Home-Bildschirm-App, wo window.print() auf iOS nichts tut). */
function loadJsPDF() {
  if (window.jspdf) return Promise.resolve(window.jspdf.jsPDF);
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = "/vendor/jspdf.umd.min.js";
    s.onload = () => res(window.jspdf.jsPDF);
    s.onerror = () => rej(new Error("PDF-Modul nicht geladen"));
    document.head.appendChild(s);
  });
}

async function buildReportPDF({ list, days, name, stats: s, effects: fx, fmtDate, fmtTime }) {
  const jsPDF = await loadJsPDF();
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const W = 210, M = 16, R = W - M, BOTTOM = 282;
  let y = 20;
  const newPageIfNeeded = (h) => { if (y + h > BOTTOM) { doc.addPage(); y = 20; } };
  const text = (t, x, size = 10, style = "normal", color = 20) => {
    doc.setFont("helvetica", style); doc.setFontSize(size); doc.setTextColor(color); doc.text(String(t), x, y);
  };
  const heading = (t) => { newPageIfNeeded(14); y += 4; text(t, M, 13, "bold"); y += 2; doc.setDrawColor(200); doc.line(M, y, R, y); y += 6; };

  const now = new Date(), from = new Date(Date.now() - days * 864e5);
  text(`Blutdruckprotokoll${name ? " \u2013 " + name : ""}`, M, 17, "bold"); y += 7;
  text(`Selbstmessung zu Hause, ${fmtDate(from)} bis ${fmtDate(now)}. Erstellt am ${fmtDate(now)}.`, M, 10, "normal", 90); y += 4;

  heading("\u00dcbersicht");
  const cells = [
    [s.morning, `morgens (${s.nMorning}\u00d7)`], [s.evening, `abends (${s.nEvening}\u00d7)`],
    [s.all, `Mittelwert aus ${s.n} Messungen`], [s.top, `h\u00f6chster Wert${s.topDate ? ", " + fmtDate(s.topDate) : ""}`],
  ];
  const cw = (R - M) / 4;
  cells.forEach(([v, l], i) => {
    const x = M + i * cw;
    doc.setFont("helvetica", "bold"); doc.setFontSize(15); doc.setTextColor(20); doc.text(String(v), x, y + 5);
    doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(90); doc.text(doc.splitTextToSize(l, cw - 3), x, y + 10);
  });
  y += 18;
  if (s.n) { text(`${s.over} % der Messungen ab 135/85.${s.pulse ? ` Puls im Mittel ${s.pulse}/min.` : ""} Morgens: 4 bis 12 Uhr, abends: ab 17 Uhr.`, M, 9, "normal", 90); y += 4; }

  heading("Verlauf");
  newPageIfNeeded(70);
  const cx = M + 10, cyTop = y, cwid = R - cx, ch = 58, lo = 50, hi = Math.max(200, ...list.map((e) => e.sys)) + 5;
  const t0 = from.getTime(), t1 = now.getTime();
  const px = (t) => cx + ((t - t0) / (t1 - t0)) * cwid;
  const py = (v) => cyTop + ch - ((v - lo) / (hi - lo)) * ch;
  doc.setDrawColor(180); doc.setLineWidth(0.2); doc.rect(cx, cyTop, cwid, ch);
  [[85, "85"], [135, "135"], [180, "180"]].forEach(([v, l]) => {
    doc.setDrawColor(v === 180 ? 200 : 170, v === 180 ? 60 : 170, v === 180 ? 60 : 170);
    doc.setLineDashPattern([1, 1], 0); doc.line(cx, py(v), cx + cwid, py(v)); doc.setLineDashPattern([], 0);
    doc.setFontSize(7); doc.setTextColor(110); doc.text(l, cx - 1.5, py(v) + 1, { align: "right" });
  });
  const sorted = [...list].sort((a, b) => new Date(a.takenAt) - new Date(b.takenAt));
  const series = (key, rgb) => {
    doc.setDrawColor(...rgb); doc.setFillColor(...rgb); doc.setLineWidth(0.5);
    sorted.forEach((e, i) => {
      const x = px(new Date(e.takenAt).getTime()), yy = py(e[key]);
      if (i) { const p = sorted[i - 1]; doc.line(px(new Date(p.takenAt).getTime()), py(p[key]), x, yy); }
      doc.circle(x, yy, 0.8, "F");
    });
  };
  series("dia", [40, 110, 200]); series("sys", [200, 50, 50]);
  doc.setFontSize(7); doc.setTextColor(110);
  doc.text(fmtDate(from), cx, cyTop + ch + 4); doc.text(fmtDate(now), cx + cwid, cyTop + ch + 4, { align: "right" });
  y = cyTop + ch + 9;
  doc.setFillColor(200, 50, 50); doc.rect(cx, y - 2, 4, 1.2, "F"); doc.text("oberer Wert (SYS)", cx + 6, y);
  doc.setFillColor(40, 110, 200); doc.rect(cx + 40, y - 2, 4, 1.2, "F"); doc.text("unterer Wert (DIA)", cx + 46, y);
  doc.text("Linien: 85, 135 (Zielwert zu Hause), 180", cx + 82, y);
  y += 4;

  const table = (cols, rows) => {
    const rowH = (r) => Math.max(...r.map((c, i) => doc.splitTextToSize(String(c), cols[i].w - 2).length)) * 4 + 2;
    const head = () => {
      newPageIfNeeded(8);
      doc.setFont("helvetica", "bold"); doc.setFontSize(8.5); doc.setTextColor(20);
      let x = M; cols.forEach((c) => { doc.text(c.t, x, y); x += c.w; });
      y += 1.5; doc.setDrawColor(150); doc.line(M, y, R, y); y += 4;
    };
    head();
    rows.forEach((r) => {
      const h = rowH(r);
      if (y + h > BOTTOM) { doc.addPage(); y = 20; head(); }
      doc.setFont("helvetica", "normal"); doc.setFontSize(8.5);
      let x = M;
      r.forEach((c, i) => {
        const hot = cols[i].hot && cols[i].hot(r);
        doc.setTextColor(...(hot ? [190, 40, 40] : [20, 20, 20]));
        doc.setFont("helvetica", hot ? "bold" : "normal");
        doc.text(doc.splitTextToSize(String(c), cols[i].w - 2), x, y); x += cols[i].w;
      });
      y += h - 4; doc.setDrawColor(225); doc.line(M, y - 1, R, y - 1); y += 4;
    });
  };

  if (fx.length) {
    heading("Mit und ohne Markierung");
    table([{ t: "Markierung", w: 70 }, { t: "mit", w: 30 }, { t: "ohne", w: 30 }, { t: "Unterschied oben", w: 48 }],
      fx.map((r) => [`${r.tag} (${r.n}\u00d7)`, r.with, r.without, `${r.diff > 0 ? "+" : ""}${r.diff}`]));
    text("Mittelwerte; ber\u00fccksichtigt ab 3 Messungen mit und ohne Markierung.", M, 8, "normal", 90); y += 4;
  }

  heading("Alle Messungen");
  const hot = (r) => Number(r[2]) >= 135 || Number(r[3]) >= 85;
  table([{ t: "Datum", w: 24 }, { t: "Uhrzeit", w: 17 }, { t: "SYS", w: 14, hot }, { t: "DIA", w: 14, hot }, { t: "Puls", w: 14 }, { t: "Markierungen, Notiz", w: R - M - 83 }],
    sorted.map((e) => { const d = new Date(e.takenAt); return [fmtDate(d), fmtTime(d), e.sys, e.dia, e.pulse ?? "", [...(e.tags || []), e.note].filter(Boolean).join(", ")]; }));
  newPageIfNeeded(8);
  text("Zielwert f\u00fcr die Selbstmessung zu Hause: unter 135/85 mmHg. Werte dar\u00fcber sind rot markiert.", M, 8, "normal", 90);

  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i); doc.setFontSize(7.5); doc.setTextColor(140);
    doc.text(`Seite ${i} von ${pages}`, R, 290, { align: "right" });
  }
  return doc.output("blob");
}
