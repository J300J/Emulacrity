from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from emulacrity.schema import EvaluationResult

VERDICT_COLORS = {
    "Recommended": colors.HexColor("#1a7f37"),
    "Conditional": colors.HexColor("#9a6700"),
    "Not Recommended": colors.HexColor("#cf222e"),
}

PILLAR_LABELS = {
    "technical_feasibility_reproducibility": "Technical Feasibility & Reproducibility",
    "target_profile_relevance": "Target Profile Relevance",
    "defensive_priority_alignment": "Defensive Priority Alignment",
    "platform_tooling_compatibility": "Platform & Tooling Compatibility",
    "supply_chain_vector": "Third-Party / Supply Chain Vector",
}


def write_pdf(result: EvaluationResult, path: Path) -> None:
    """Render an EvaluationResult as a PDF — a direct transcription of the JSON output."""
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    body_style = styles["BodyText"]
    verdict_style = ParagraphStyle(
        "Verdict",
        parent=styles["Heading1"],
        textColor=VERDICT_COLORS.get(result.verdict, colors.black),
    )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=letter,
        title=f"Emulacrity Evaluation — {result.actor}",
    )
    story: list = []

    story.append(Paragraph(f"Emulacrity Evaluation: {escape(result.actor)}", title_style))
    if result.aliases:
        story.append(Paragraph(f"Aliases: {escape(', '.join(result.aliases))}", body_style))
    story.append(Paragraph(f"Mode: {escape(result.mode)}", body_style))
    story.append(Spacer(1, 0.2 * inch))

    story.append(
        Paragraph(f"{escape(result.verdict)} — {result.weighted_total:.1f}/100", verdict_style)
    )
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("Pillar Scores", heading_style))
    table_data = [["Pillar", "Score", "Justification"]]
    for field_name, label in PILLAR_LABELS.items():
        pillar = getattr(result.scores, field_name)
        table_data.append(
            [
                label,
                f"{pillar.score}/5",
                Paragraph(escape(pillar.justification), body_style),
            ]
        )

    table = Table(table_data, colWidths=[1.6 * inch, 0.6 * inch, 4.0 * inch], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    if result.sources:
        story.append(Paragraph("Sources", heading_style))
        for s in result.sources:
            label = escape(s.title or s.url or "(untitled)")
            meta_parts = []
            if s.publisher:
                meta_parts.append(escape(s.publisher))
            if s.publish_date:
                meta_parts.append(escape(s.publish_date))
            flags = []
            if s.on_allowlist:
                flags.append("trusted")
            if s.within_18_months:
                flags.append("recent")
            if flags:
                meta_parts.append(f"[{', '.join(flags)}]")
            meta = " — ".join(meta_parts) if meta_parts else ""
            line = f"• {label}" + (f" — {meta}" if meta else "")
            story.append(Paragraph(line, body_style))
        story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Notes", heading_style))
    story.append(Paragraph(escape(result.notes) if result.notes else "—", body_style))

    doc.build(story)
