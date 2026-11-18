# Submission checklist

## Folder
- `paper/`  beyond_provenance.tex, references.bib, and `figures/` (put Figure_1.pdf to Figure_4.pdf here; the .tex expects them next to it, so copy them beside the .tex or set \graphicspath{{figures/}})
- `artifact/`  anonymised code, tests and logs (`obe` package); `beyond-provenance-artifact.zip` is the same folder zipped for upload
- `_to_delete/`  one stale folder; delete it yourself

## Figures (I could not open the PDFs; check each against the revised text)
1. Figure 4 axis labels: the paper no longer calls the measured axes S and U. Relabel the axes "Harmful sends held (%)" and "Hand-off tasks completed (%)". Keep the dashed S + U = 1 line, labelled as the twin-pair bound.
2. All figures: search the artwork for old wording and fix any you find: "Proposition 3", "Proposition 4" (now Proposition 2 and Remark 1), "six models" or "Phi-4" (now five models), "grant raises compliance".
3. Figure 2: if it shows anything an agent can write into the binding store, remove it; the paper now says no agent can write B (Section 3.3).
4. Figures 1 and 3 need no change if they match their captions.

## Before upload
- Compile with the real IEEEtran class (checked here only with a stand-in class: no errors, no undefined references).
- Upload `beyond-provenance-artifact.zip` to an anonymous host (for example anonymous.4open.science) and add the link where the paper says the testbed will be released (Section 9.2).
- Do not upload the original `out-of-reach` folder: it contains the sprint name, Windows paths and personal guides.
