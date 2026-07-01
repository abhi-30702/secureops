# INSTRUCTIONDOCUMENT.md — How to Generate the SecureOps Word Document

> **Read this first, then do the work.** You are a Claude Code session running on a
> **Windows** machine. Your job is to convert `DOCUMENTATIONCLAUDE.md` (the documentation
> source, in the same folder) into a **professional Microsoft Word `.docx`** project
> report named **`SecureOps_Project_Documentation.docx`**.
>
> Do not rewrite or invent project content — `DOCUMENTATIONCLAUDE.md` is the single source
> of truth. Your task is **formatting and assembly**, plus a title page, table of contents,
> and page numbers. Keep all section text, tables, and ASCII diagrams intact.

---

## 0. Inputs and Output

- **Input:** `DOCUMENTATIONCLAUDE.md` (this folder).
- **Output:** `SecureOps_Project_Documentation.docx` (this folder).
- **Optional intermediate:** `reference.docx` (a style template you generate once).

---

## 1. Skills / Capabilities You Will Use

1. **Shell access** — run PowerShell/CMD commands (install tools, run Pandoc and Python).
2. **File read/write** — read `DOCUMENTATIONCLAUDE.md`; write small Python scripts.
3. **Python scripting** — `python-docx` for the title page, page numbers, and font fixes.
4. **Pandoc** — Markdown → `.docx` conversion (handles headings, tables, code blocks, TOC).

If a tool is missing, install it (Section 3). Prefer **Method A (Pandoc + python-docx
post-process)** — it is the most reliable. Use **Method B (pure python-docx)** only if
Pandoc cannot be installed.

---

## 2. Target Format Specification (what "done" looks like)

- **Page:** A4, portrait, 1-inch (2.54 cm) margins.
- **Body font:** Calibri 11 pt (or Times New Roman 12 pt if the institution requires it),
  line spacing 1.15–1.5, justified.
- **Headings:** numbered, hierarchical, bold; Heading 1 ~16 pt, Heading 2 ~14 pt,
  Heading 3 ~12 pt, accent colour dark slate (`#1F3A5F`) or black.
- **Title page (page i, no number shown):**
  - Project title: *SecureOps — A Unified Desktop Penetration-Testing, Incident-Response &
    Security-Audit Platform*
  - Subtitle: *Project Documentation*
  - Organisation: *the organisation (Internal Security Team)*
  - Platform/Version: *Kali Linux · Version 1.2*
  - Space for: Author name(s), Guide/Supervisor, Department, Institution, Date
    (leave labelled placeholders the user can fill).
- **Table of Contents:** auto-generated, on its own page after the title page.
- **Page numbers:** bottom-centre; the title page and TOC use roman numerals (i, ii) or no
  number, and the body starts at Arabic "1" — if that is hard to automate, a continuous
  Arabic numbering starting at 1 on the body is acceptable.
- **Tables:** Word table with a shaded header row, thin borders, no oversized columns.
- **ASCII diagrams** (ER, DFD-1, DFD-2, architecture, activity): rendered in a **monospace
  font (Consolas 8–9 pt)** inside the code/verbatim style so alignment is preserved. They
  must **not** wrap — shrink the font until each block fits the page width.
- **Code snippets:** monospace, light-grey background or boxed, 9–10 pt.
- Add a short **caption** under each diagram (e.g., "Figure 1. Layered Architecture",
  "Figure 2. ER Diagram", "Figure 3. DFD Level 1", "Figure 4. DFD Level 2",
  "Figure 5. Activity Diagram").

---

## 3. Prerequisites — Install on Windows

Run these in **PowerShell**. Check each tool first; install only what's missing.

```powershell
# Python (skip if 'python --version' already works)
winget install --id Python.Python.3.12 -e --source winget

# Pandoc
winget install --id JohnMacFarlane.Pandoc -e --source winget

# python-docx (for title page, page numbers, font fixes)
python -m pip install --upgrade pip
python -m pip install python-docx
```

Verify:
```powershell
python --version
pandoc --version
python -c "import docx; print('python-docx OK')"
```

(If `winget` is unavailable: install Python from python.org, Pandoc from
https://pandoc.org/installing.html, then `pip install python-docx`.)

---

## 4. Method A — Pandoc + python-docx Post-Process (RECOMMENDED)

### Step A1 — Create a style template (`reference.docx`)
Generate Pandoc's default reference doc, which you will tweak for fonts/styles:
```powershell
pandoc -o reference.docx --print-default-data-file reference.docx
```
Then adjust its styles with a short python-docx script (`style_reference.py`):

```python
from docx import Document
from docx.shared import Pt, RGBColor

doc = Document("reference.docx")
def set_style(name, font=None, size=None, bold=None, color=None):
    if name not in doc.styles: return
    f = doc.styles[name].font
    if font:  f.name = font
    if size:  f.size = Pt(size)
    if bold is not None: f.bold = bold
    if color: f.color.rgb = RGBColor.from_string(color)

set_style("Normal",   font="Calibri", size=11)
set_style("Heading 1", font="Calibri", size=16, bold=True, color="1F3A5F")
set_style("Heading 2", font="Calibri", size=14, bold=True, color="1F3A5F")
set_style("Heading 3", font="Calibri", size=12, bold=True, color="1F3A5F")
# Monospace for code blocks AND ASCII diagrams — small enough that diagrams don't wrap.
for s in ("Source Code", "Verbatim Char"):
    set_style(s, font="Consolas", size=8)
doc.save("reference.docx")
print("reference.docx styled")
```
Run: `python style_reference.py`

### Step A2 — Convert Markdown → Word
```powershell
pandoc "DOCUMENTATIONCLAUDE.md" `
  --from gfm `
  --reference-doc reference.docx `
  --toc --toc-depth=3 `
  -o "_body.docx"
```
This produces a body document with styled headings, Word tables, a TOC list, and
monospace code/diagram blocks.

### Step A3 — Add title page + page numbers (`finalize.py`)
Post-process `_body.docx` into the final file:

```python
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Pt

doc = Document("_body.docx")

# ---- Page numbers in the footer (centre) ----
def add_page_numbers(document):
    for section in document.sections:
        footer = section.footer
        p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run()
        fld1 = OxmlElement('w:fldChar'); fld1.set(qn('w:fldCharType'), 'begin')
        instr = OxmlElement('w:instrText'); instr.set(qn('xml:space'), 'preserve'); instr.text = 'PAGE'
        fld2 = OxmlElement('w:fldChar'); fld2.set(qn('w:fldCharType'), 'end')
        run._r.append(fld1); run._r.append(instr); run._r.append(fld2)

add_page_numbers(doc)

# ---- Title page: insert paragraphs before everything, then a page break ----
def insert_paragraph_at_start(document, text, size, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER):
    body = document.element.body
    p = document.add_paragraph()
    body.insert(0, p._p)             # move to the very top
    p.alignment = align
    r = p.add_run(text); r.bold = bold; r.font.size = Pt(size)
    return p

# Build from bottom-up because each insert goes to index 0.
for text, size in [
    ("Date: ____________________", 12),
    ("Department / Institution: ____________________", 12),
    ("Guide / Supervisor: ____________________", 12),
    ("Submitted by: ____________________", 12),
    ("", 12),
    ("Kali Linux  ·  Version 1.2", 12),
    ("the organisation — Internal Security Team", 13),
    ("", 8),
    ("Project Documentation", 16),
    ("SecureOps", 30),
    ("A Unified Desktop Penetration-Testing, Incident-Response & Security-Audit Platform", 13),
]:
    insert_paragraph_at_start(doc, text, size)

# Page break after the title block (the first paragraph after the title set).
brk = doc.paragraphs[11]  # the empty spacer right after the title set
run = brk.add_run(); run.add_break(WD_BREAK.PAGE)

doc.save("SecureOps_Project_Documentation.docx")
print("Wrote SecureOps_Project_Documentation.docx")
```
Run: `python finalize.py`

> **Note on the TOC:** Pandoc's `--toc` inserts a static list. When the user first opens the
> file in Word, they can press **Ctrl+A then F9** to refresh fields (TOC + page numbers).
> Mention this in your final message to the user.

### Step A4 — Verify the diagrams didn't wrap
Open the doc (or inspect) and confirm each ASCII diagram block is intact and not line-wrapped.
If any diagram wraps, lower the "Source Code"/"Verbatim Char" font size in `style_reference.py`
(e.g., 8 → 7 pt) and re-run A1–A3.

---

## 5. Method B — Pure python-docx (FALLBACK, if Pandoc unavailable)

Write a script that walks `DOCUMENTATIONCLAUDE.md` line by line and emits Word elements:
- Lines starting `# / ## / ###` → `Heading 1/2/3`.
- Markdown pipe tables (`| … |`) → `document.add_table(...)` with a shaded header row
  (`style="Light Grid Accent 1"`), one row per data line, skipping the `|---|` separator.
- Fenced code blocks (between ```` ``` ````) → a single paragraph in a **Consolas 8 pt**
  run, each source line as its own line (`add_break`), optionally inside a 1-cell bordered
  table to create a "box".
- Normal lines → body paragraphs (handle `**bold**` and `` `code` `` inline if feasible;
  otherwise emit plain text — content fidelity matters more than inline styling).
- Then reuse the **title page** and **page-number** helpers from Step A3.

Keep it robust: if a construct is ambiguous, fall back to plain text rather than dropping
content. **Never drop a section, table, or diagram.**

---

## 6. Diagram Handling (detail)

**Primary approach (reliable):** keep the ASCII diagrams as monospace code blocks (above).
This guarantees they render exactly as written, with captions added beneath.

**Optional upgrade (nicer visuals):** recreate the diagrams in **PlantUML** and embed as
images. Only do this if the user explicitly asks for vector diagrams. Mapping:
- ER diagram → PlantUML `@startuml … entity/relationship …`
- DFD-1 / DFD-2 → PlantUML `@startuml … rectangle/arrow …` (or a simple flow)
- Activity diagram → PlantUML `@startuml … start; if/else; fork; stop; @enduml`
Render with the PlantUML jar or an online server to PNG, then `document.add_picture(...)`.
If you take this path, still keep the monospace block as a fallback in an appendix.

---

## 7. Step-by-Step Task List (do these in order)

1. Confirm `DOCUMENTATIONCLAUDE.md` exists in the working folder; read it.
2. Ensure Python, Pandoc, and python-docx are installed (Section 3).
3. Method A → generate and style `reference.docx` (Steps A1).
4. Convert to `_body.docx` with Pandoc (Step A2).
5. Run `finalize.py` to add the title page and page numbers (Step A3) → produce
   `SecureOps_Project_Documentation.docx`.
6. Verify diagrams/tables (Step A4); adjust font size if any diagram wraps.
7. Clean up intermediates (`_body.docx`, scripts) if the user wants only the final file.
8. Report the output path and tell the user to press **Ctrl+A → F9** in Word once to
   refresh the TOC and page numbers.

---

## 8. Quality Checklist (acceptance criteria)

- [ ] File opens in Microsoft Word without a repair prompt.
- [ ] Title page present with project title, org, version, and labelled placeholders.
- [ ] Table of Contents present (refreshable) with all 13 sections.
- [ ] All sections 1–13 present, in order, with no dropped content.
- [ ] Every table rendered as a real Word table (not raw `| pipes |`).
- [ ] All five+ ASCII diagrams intact, monospace, **not wrapped**, each with a caption.
- [ ] Code snippets in monospace and readable.
- [ ] Page numbers in the footer.
- [ ] Consistent heading styles and body font throughout.

---

## 9. Ready-to-Paste Starter Prompt (for the new Claude Code session on Windows)

> Copy everything between the lines into the fresh Claude Code session opened in the folder
> that contains `DOCUMENTATIONCLAUDE.md` and `INSTRUCTIONDOCUMENT.md`.

```
Read INSTRUCTIONDOCUMENT.md and follow it exactly to convert DOCUMENTATIONCLAUDE.md into a
professional Word document named SecureOps_Project_Documentation.docx.

Requirements:
- Use Method A (Pandoc + python-docx post-process). Install Python, Pandoc, and
  python-docx first if they are missing (PowerShell/winget).
- Preserve ALL content, tables, and the ASCII diagrams (ER, DFD-1, DFD-2, architecture,
  activity) exactly — render diagrams as monospace (Consolas ~8pt) so they do not wrap,
  and add a caption under each.
- Add a title page (project title, "Project Documentation", the organisation, Kali Linux ·
  Version 1.2, and labelled placeholders for Submitted by / Guide / Department / Date),
  an auto Table of Contents, numbered headings, and footer page numbers.
- A4, 1-inch margins, Calibri 11pt body, justified.
- When done, verify no diagram wrapped, list the output file path, and tell me to press
  Ctrl+A then F9 in Word to refresh the TOC and page numbers.

Work step by step, run the commands yourself, and show me the results.
```

---

## 10. Troubleshooting

- **A diagram wraps / misaligns:** lower the monospace style size (8 → 7 pt) in
  `style_reference.py`, re-run; or set that section's page to landscape.
- **TOC shows "No table of contents entries":** in Word press **Ctrl+A → F9**, or
  right-click the TOC → *Update Field* → *Update entire table*.
- **Tables overflow the page:** set table AutoFit to "Fit to window", or reduce table font
  to 10 pt.
- **`winget` not found:** install Python and Pandoc manually from their official sites,
  then `pip install python-docx`.
- **Pandoc cannot install at all:** use Method B (pure python-docx) — it has no external
  dependency beyond python-docx.
- **Unicode/box-drawing characters look wrong:** ensure the monospace style uses a font
  with box-drawing glyphs (Consolas works); keep the file UTF-8.

---

*This instruction file is self-contained: a fresh Claude Code session needs only
`DOCUMENTATIONCLAUDE.md`, `INSTRUCTIONDOCUMENT.md`, and the prompt in Section 9 to produce
the final Word document.*
