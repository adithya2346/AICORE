import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def build_presentation(output_path):
    prs = Presentation()
    # 16:9 Widescreen dimensions
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Color Palette - Modern Cyber / Dark Tech
    BG_COLOR = RGBColor(11, 19, 43)        # Deep Navy #0B132B
    CARD_BG = RGBColor(20, 32, 65)         # Elevated Slate #142041
    ACCENT_CYAN = RGBColor(0, 229, 255)    # Electric Cyan #00E5FF
    ACCENT_PURPLE = RGBColor(129, 140, 248)# Soft Indigo #818CF8
    TEXT_LIGHT = RGBColor(248, 250, 252)   # Near White #F8FAFC
    TEXT_MUTED = RGBColor(148, 163, 184)   # Slate Gray #94A3B8
    ACCENT_GREEN = RGBColor(52, 211, 153)  # Emerald #34D399
    ACCENT_ROSE = RGBColor(251, 113, 133)  # Rose Red #FB7185

    blank_layout = prs.slide_layouts[6]

    def set_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.color.rgb = BG_COLOR
        return bg

    def add_header(slide, title_text, category_text="AI DATA RECOVERY SYSTEM"):
        # Category Tag
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.45), Inches(10), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = ACCENT_CYAN

        # Title
        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.8), Inches(11.5), Inches(0.8))
        tf_t = t_box.text_frame
        tf_t.word_wrap = True
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.size = Pt(26)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_LIGHT

    def create_card(slide, left, top, width, height, bg_color=CARD_BG, border_color=None):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        if border_color:
            card.line.color.rgb = border_color
            card.line.width = Pt(1.5)
        else:
            card.line.color.rgb = RGBColor(30, 45, 85)
            card.line.width = Pt(1)
        return card

    # ==========================================
    # SLIDE 1: TITLE SLIDE
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_background(s1)

    # Accent decorative glow rectangle
    glow = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.8), Inches(0.15), Inches(3.8))
    glow.fill.solid()
    glow.fill.fore_color.rgb = ACCENT_CYAN
    glow.line.fill.background()

    # Main Title
    tbox = s1.shapes.add_textbox(Inches(1.2), Inches(1.6), Inches(11), Inches(2.2))
    tf = tbox.text_frame
    tf.word_wrap = True
    p0 = tf.paragraphs[0]
    p0.text = "AI-Driven Autonomous Data Recovery"
    p0.font.size = Pt(38)
    p0.font.bold = True
    p0.font.color.rgb = TEXT_LIGHT

    p1 = tf.add_paragraph()
    p1.text = "& Forensic File Self-Healing System"
    p1.font.size = Pt(36)
    p1.font.bold = True
    p1.font.color.rgb = ACCENT_CYAN

    # Subtitle
    sub_box = s1.shapes.add_textbox(Inches(1.2), Inches(4.0), Inches(10.5), Inches(1.2))
    tf_sub = sub_box.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = "Recovering 'Permanently Deleted' Files via Deep Physical Carving, Bipartite Graph Fragment Stitching, and Zero-Fabrication Structural Repair."
    p_sub.font.size = Pt(16)
    p_sub.font.color.rgb = TEXT_MUTED

    # Meta Cards at bottom
    badges = [
        ("CORE INNOVATION", "AI Graph Fragment Reassembly"),
        ("FORENSIC INVARIANT", "0% Fake Bytes Injected"),
        ("COMPATIBILITY", "NTFS / FAT32 / exFAT / Ext4")
    ]
    for i, (tag, val) in enumerate(badges):
        bx = Inches(1.2 + i * 3.7)
        create_card(s1, bx, Inches(5.6), Inches(3.4), Inches(1.1))
        tb = s1.shapes.add_textbox(bx + Inches(0.2), Inches(5.7), Inches(3.0), Inches(0.9))
        ptg = tb.text_frame.paragraphs[0]
        ptg.text = tag
        ptg.font.size = Pt(10)
        ptg.font.bold = True
        ptg.font.color.rgb = ACCENT_PURPLE

        pval = tb.text_frame.add_paragraph()
        pval.text = val
        pval.font.size = Pt(13)
        pval.font.bold = True
        pval.font.color.rgb = TEXT_LIGHT

    # ==========================================
    # SLIDE 2: THE PROBLEM
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_background(s2)
    add_header(s2, "The Real-World Crisis of Data Loss & Legacy Pitfalls", "Problem Statement")

    prob_cards = [
        ("The 'Permanently Deleted' Illusion",
         "Users believe Shift+Delete or Recycle Bin emptying destroys files forever.\n\nIn reality, only directory pointers are unlinked, while raw disk blocks persist until overwritten — but legacy tools fail to reconstruct them.",
         ACCENT_ROSE),
        ("The Fragmented Sector Blindspot",
         "When SSDs/HDDs write data across non-contiguous clusters, traditional tools only recover the first block.\n\nThe remainder is abandoned, resulting in corrupt, halved, or unopenable files.",
         ACCENT_ROSE),
        ("The 'Hallucination' / Corrupt Bytes Trap",
         "Commercial recovery utilities often fill damaged sectors with random null bytes or corrupted headers.\n\nFiles fail hash verification, CRC checksums, and forensic admissibility in audits/court.",
         ACCENT_ROSE)
    ]

    for i, (title, desc, color) in enumerate(prob_cards):
        cx = Inches(0.8 + i * 3.95)
        create_card(s2, cx, Inches(1.9), Inches(3.7), Inches(4.8), border_color=color)
        tb = s2.shapes.add_textbox(cx + Inches(0.25), Inches(2.1), Inches(3.2), Inches(4.3))
        tf = tb.text_frame
        tf.word_wrap = True
        p_t = tf.paragraphs[0]
        p_t.text = f"0{i+1}. {title}"
        p_t.font.size = Pt(16)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_LIGHT

        p_d = tf.add_paragraph()
        p_d.text = "\n" + desc
        p_d.font.size = Pt(13)
        p_d.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 3: OUR SOLUTION
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_background(s3)
    add_header(s3, "Autonomous Two-Pillar Architecture", "Solution Overview")

    sol_cards = [
        ("PILLAR 1: FORENSIC PHYSICAL CARVER",
         "Raw Disk & Unallocated Space Recovery",
         [
             "Master File Table (MFT) unallocated record scanner",
             "Direct raw disk cluster carving using magic byte signatures",
             "Volume Shadow Copy (VSS) delta harvesting",
             "Works even if the filesystem or partition is corrupted"
         ],
         ACCENT_CYAN),
        ("PILLAR 2: UNIVERSAL SELF-HEALING ENGINE",
         "Structural Repair with 0% Fake Byte Guarantee",
         [
             "Deterministic header/footer & marker alignment",
             "Automatic CRC32 recalculation & linear XREF rebuilds",
             "Native support for JPEG, PNG, PDF, DOCX/XLSX, SQLite, MP4",
             "In-place overwrite with zero secondary corruption"
         ],
         ACCENT_GREEN)
    ]

    for i, (badge, title, points, col) in enumerate(sol_cards):
        cx = Inches(0.8 + i * 5.95)
        create_card(s3, cx, Inches(1.9), Inches(5.7), Inches(4.8), border_color=col)
        tb = s3.shapes.add_textbox(cx + Inches(0.35), Inches(2.2), Inches(5.0), Inches(4.2))
        tf = tb.text_frame
        tf.word_wrap = True
        
        pb = tf.paragraphs[0]
        pb.text = badge
        pb.font.size = Pt(12)
        pb.font.bold = True
        pb.font.color.rgb = col

        pt = tf.add_paragraph()
        pt.text = title
        pt.font.size = Pt(20)
        pt.font.bold = True
        pt.font.color.rgb = TEXT_LIGHT

        for pt_item in points:
            p = tf.add_paragraph()
            p.text = f"•  {pt_item}"
            p.font.size = Pt(13)
            p.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 4: HOW PERMANENT DELETION RECOVERY WORKS
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_background(s4)
    add_header(s4, "Deep Dive: How 'Permanently Deleted' Data Is Retrieved", "Forensic Mechanics")

    steps = [
        ("Step 1: Low-Level Storage Access",
         "Bypasses the OS file manager via raw block device handles (\\\\.\\PhysicalDriveX).\nAccesses sectors directly without requiring OS permission locks.",
         ACCENT_CYAN),
        ("Step 2: MFT & Metadata Scrape",
         "Inspects the Master File Table for records flagged with IN_USE = 0.\nExtracts cluster run-lists, original timestamps, and file sizes before overwrite.",
         ACCENT_PURPLE),
        ("Step 3: Magic Byte Carving",
         "Scans unallocated clusters for binary headers (e.g. FFD8FFE0 for JPEG, %PDF-1.x for PDF, PK\\x03\\x04 for Office/ZIP) to detect orphan data.",
         ACCENT_CYAN),
        ("Step 4: Shadow Vault Harvesting",
         "Queries Volume Shadow Copies and system restore snapshots to capture clean pre-deletion states and delta block chains.",
         ACCENT_GREEN)
    ]

    for i, (title, desc, col) in enumerate(steps):
        cx = Inches(0.8 + (i % 2) * 5.95)
        cy = Inches(1.9 + (i // 2) * 2.5)
        create_card(s4, cx, cy, Inches(5.7), Inches(2.2), border_color=col)
        tb = s4.shapes.add_textbox(cx + Inches(0.25), cy + Inches(0.2), Inches(5.2), Inches(1.8))
        tf = tb.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = title
        pt.font.size = Pt(15)
        pt.font.bold = True
        pt.font.color.rgb = TEXT_LIGHT

        pd = tf.add_paragraph()
        pd.text = desc
        pd.font.size = Pt(12)
        pd.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 5: AI GRAPH FRAGMENT REASSEMBLY
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_background(s5)
    add_header(s5, "Solving Non-Contiguous Fragmentation with AI & Graph Theory", "AI Core")

    # Left Card: Theoretical Model
    create_card(s5, Inches(0.8), Inches(1.9), Inches(5.7), Inches(4.8))
    tb_l = s5.shapes.add_textbox(Inches(1.1), Inches(2.2), Inches(5.1), Inches(4.2))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True
    p = tf_l.paragraphs[0]
    p.text = "The Mathematical Framework"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = ACCENT_CYAN

    math_pts = [
        "Problem: When a 50MB video or PDF is scattered into 12 non-sequential cluster runs, brute-force order testing is O(N!) factorial.",
        "Feature Extraction: Shannon entropy, byte frequency distribution (n-grams), and gradient boundary continuity.",
        "Bipartite Graph Formulation: Unallocated fragments become nodes; boundary transition probabilities become edge weights.",
        "Kuhn-Munkres (Hungarian) & TSP Solver: Finds the globally optimal path that stitches blocks in micro-seconds."
    ]
    for m in math_pts:
        p = tf_l.add_paragraph()
        p.text = f"•  {m}"
        p.font.size = Pt(12.5)
        p.font.color.rgb = TEXT_MUTED

    # Right Card: AI Pipeline
    create_card(s5, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8), border_color=ACCENT_PURPLE)
    tb_r = s5.shapes.add_textbox(Inches(7.1), Inches(2.2), Inches(5.1), Inches(4.2))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "Fragment Reassembly Pipeline"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = ACCENT_PURPLE

    stages = [
        ("1. Clustering Classifier", "RandomForest + Entropy scoring categorizes unknown blocks into text, image, executable, or compressed."),
        ("2. Boundary Cross-Entropy", "Evaluates byte transition smoothness between cluster tails and potential next cluster heads."),
        ("3. Structural Constraint Verification", "Validates inner headers (JPEG scan markers, PDF xref offsets, ZIP local file headers)."),
        ("4. Graph Pruning & Output", "Produces an assembled byte stream with mathematically verified continuity.")
    ]
    for st, sd in stages:
        p = tf_r.add_paragraph()
        p.text = st
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = TEXT_LIGHT

        p2 = tf_r.add_paragraph()
        p2.text = sd
        p2.font.size = Pt(12)
        p2.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 6: UNIVERSAL FILE REPAIR ENGINE
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_background(s6)
    add_header(s6, "Universal File Repair: Multi-Format Self-Healing", "Forensic File Repair")

    formats = [
        ("JPEG / JPG", "Aligns SOI/EOI; cleans corrupt EXIF; sanitizes bad markers (0xFF00 stuffing); neutralizes duplicate SOF chunks.", ACCENT_CYAN),
        ("PNG Images", "Reconstructs 8-byte PNG signature; recomputes CRC32 checksums on IDAT/IHDR chunks; injects missing IEND footer.", ACCENT_PURPLE),
        ("PDF Documents", "Detects shifted %PDF- headers; rebuilds missing cross-reference (xref) tables; injects valid trailer & %%EOF.", ACCENT_GREEN),
        ("ZIP / Office (DOCX/XLSX)", "Scans for PK\\x03\\x04 local headers; synthesizes missing Central Directory records and EOCD markers.", ACCENT_CYAN),
        ("SQLite Databases", "Restores standard 'SQLite format 3\\x00' header, normalized page size (4096), and write version flags.", ACCENT_PURPLE),
        ("Text / JSON / CSV", "Strips corrupted null bytes; repairs UTF-8 encodings; auto-closes truncated JSON bracket stacks safely.", ACCENT_GREEN)
    ]

    for i, (fmt, detail, col) in enumerate(formats):
        cx = Inches(0.8 + (i % 3) * 3.95)
        cy = Inches(1.9 + (i // 3) * 2.5)
        create_card(s6, cx, cy, Inches(3.7), Inches(2.2), border_color=col)
        tb = s6.shapes.add_textbox(cx + Inches(0.2), cy + Inches(0.18), Inches(3.3), Inches(1.8))
        tf = tb.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = fmt
        pt.font.size = Pt(15)
        pt.font.bold = True
        pt.font.color.rgb = col

        pd = tf.add_paragraph()
        pd.text = detail
        pd.font.size = Pt(11.5)
        pd.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 7: ZERO FABRICATION GUARANTEE
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_background(s7)
    add_header(s7, "Forensic Integrity: The 0% Fake Bytes Invariant", "Trust & Admissibility")

    # Big Central Metric Card
    create_card(s7, Inches(0.8), Inches(1.9), Inches(11.7), Inches(1.8), border_color=ACCENT_CYAN)
    tb_m = s7.shapes.add_textbox(Inches(1.2), Inches(2.1), Inches(11.0), Inches(1.4))
    tf_m = tb_m.text_frame
    tf_m.word_wrap = True
    pm_t = tf_m.paragraphs[0]
    pm_t.text = "CORE FORENSIC INVARIANT: fabricated_bytes == 0"
    pm_t.font.size = Pt(22)
    pm_t.font.bold = True
    pm_t.font.color.rgb = ACCENT_CYAN

    pm_d = tf_m.add_paragraph()
    pm_d.text = "Our system NEVER invents or hallucinates fake payload bytes. Repairs are strictly topological and structural (fixing container syntax, container markers, checksums, and reference trees) without fabricating missing payload data."
    pm_d.font.size = Pt(13)
    pm_d.font.color.rgb = TEXT_LIGHT

    # 3 Comparison Columns
    comps = [
        ("Traditional 'Fixers'", "Injects repeating 0x00 null bytes or random pads. Corrupts application parsers, invalidates hashes, renders files legally void.", ACCENT_ROSE),
        ("Generative AI Tools", "Synthesizes fake imagery or hallucinated text. Unacceptable in corporate audits, criminal forensics, or accounting records.", ACCENT_ROSE),
        ("Our Deterministic Repair", "Forensically sound. Preserves 100% of authentic original payload bytes while restoring OS/viewer compatibility.", ACCENT_GREEN)
    ]
    for i, (title, desc, col) in enumerate(comps):
        cx = Inches(0.8 + i * 3.95)
        create_card(s7, cx, Inches(4.0), Inches(3.7), Inches(2.7), border_color=col)
        tb = s7.shapes.add_textbox(cx + Inches(0.2), Inches(4.2), Inches(3.3), Inches(2.3))
        tf = tb.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = title
        pt.font.size = Pt(15)
        pt.font.bold = True
        pt.font.color.rgb = col

        pd = tf.add_paragraph()
        pd.text = desc
        pd.font.size = Pt(12)
        pd.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 8: SYSTEM ARCHITECTURE & TECH STACK
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_background(s8)
    add_header(s8, "End-to-End System Architecture", "Technical Stack")

    stack_cards = [
        ("Presentation Layer", "PyQt6 Desktop App & Modern React Dashboard",
         ["Fluent Dark UI with High-DPI support", "Real-time cluster fragment graph", "Live hex inspection & visual metrics", "Cross-platform ready"],
         ACCENT_CYAN),
        ("Asynchronous Engine", "FastAPI, Worker Threads & SQLite DB",
         ["Non-blocking disk I/O background worker", "Stateful recovery job tracking", "Real-time websocket / polling telemetry", "Thread-safe disk read locks"],
         ACCENT_PURPLE),
        ("Intelligence & Repair", "ML Classifier & Universal File Repair",
         ["RandomForest + Shannon Entropy", "Deterministic header/footer aligners", "Bipartite Hungarian fragment optimizer", "Zero-Fabrication verification engine"],
         ACCENT_GREEN)
    ]

    for i, (tier, title, bullets, col) in enumerate(stack_cards):
        cx = Inches(0.8 + i * 3.95)
        create_card(s8, cx, Inches(1.9), Inches(3.7), Inches(4.8), border_color=col)
        tb = s8.shapes.add_textbox(cx + Inches(0.25), Inches(2.1), Inches(3.2), Inches(4.3))
        tf = tb.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = tier.upper()
        pt.font.size = Pt(11)
        pt.font.bold = True
        pt.font.color.rgb = col

        ptt = tf.add_paragraph()
        ptt.text = title
        ptt.font.size = Pt(15)
        ptt.font.bold = True
        ptt.font.color.rgb = TEXT_LIGHT

        for b in bullets:
            p = tf.add_paragraph()
            p.text = f"•  {b}"
            p.font.size = Pt(12)
            p.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 9: LIVE DEMO WALKTHROUGH
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    set_background(s9)
    add_header(s9, "Live Workflow: 4-Stage Autonomous Recovery", "Product Walkthrough")

    demo_stages = [
        ("STAGE 1", "Target Ingestion", "Select target drive (Physical / Logical) or drag-and-drop a corrupted file. Immediate low-level telemetry begins."),
        ("STAGE 2", "Integrity Diagnosis", "Deep structural audit scans for missing headers, shifted offsets, corrupt CRC checksums, and truncated tails."),
        ("STAGE 3", "AI Reconstruction", "ML classifier groups clusters; Hungarian algorithm solves non-contiguous links; structural repair engine heals container syntax."),
        ("STAGE 4", "Forensic Delivery", "In-place safe overwrite or isolated extraction. Generates SHA-256 cryptographic audit receipt with 0% fake byte confirmation.")
    ]

    for i, (badge, title, desc) in enumerate(demo_stages):
        cx = Inches(0.8 + i * 2.95)
        create_card(s9, cx, Inches(1.9), Inches(2.75), Inches(4.8))
        tb = s9.shapes.add_textbox(cx + Inches(0.18), Inches(2.1), Inches(2.4), Inches(4.3))
        tf = tb.text_frame
        tf.word_wrap = True
        
        pb = tf.paragraphs[0]
        pb.text = badge
        pb.font.size = Pt(11)
        pb.font.bold = True
        pb.font.color.rgb = ACCENT_CYAN

        pt = tf.add_paragraph()
        pt.text = title
        pt.font.size = Pt(15)
        pt.font.bold = True
        pt.font.color.rgb = TEXT_LIGHT

        pd = tf.add_paragraph()
        pd.text = desc
        pd.font.size = Pt(12)
        pd.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 10: COMPETITIVE ADVANTAGE
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    set_background(s10)
    add_header(s10, "Why Our Platform Outperforms Industry Standard Tools", "Competitive Benchmark")

    # Table Card
    create_card(s10, Inches(0.8), Inches(1.9), Inches(11.7), Inches(4.8))
    tb_table = s10.shapes.add_textbox(Inches(1.1), Inches(2.1), Inches(11.1), Inches(4.4))
    tf_t = tb_table.text_frame
    tf_t.word_wrap = True

    features = [
        ("Feature / Capability", "Legacy Tools (Recuva, EaseUS)", "Open Source (TestDisk)", "Our AI Forensic Engine"),
        ("Non-Contiguous Fragment Stitching", "Fails (halved/broken files)", "Manual Hex Scripting", "Automated AI Graph Optimizer"),
        ("Damaged File Self-Healing", "None (Paid addon or external)", "Basic partition rebuild only", "Native Universal File Repair"),
        ("Forensic Invariant Guarantee", "Unknown / Undocumented", "Varies", "Strict 0% Fake Bytes Injected"),
        ("Modern Multi-Modal Interface", "Dated 2000s-style Windows GUI", "Pure CLI / Terminal only", "Modern PyQt6 + React Web Dashboard"),
        ("In-Place Direct File Repair", "No (Exports copies only)", "No", "Yes (Safe direct target repair)")
    ]

    for row_idx, (c1, c2, c3, c4) in enumerate(features):
        p = tf_t.paragraphs[0] if row_idx == 0 else tf_t.add_paragraph()
        p.text = f"{c1:<34} | {c2:<28} | {c3:<24} | {c4}"
        if row_idx == 0:
            p.font.size = Pt(12)
            p.font.bold = True
            p.font.color.rgb = ACCENT_CYAN
        else:
            p.font.size = Pt(11.5)
            p.font.color.rgb = TEXT_LIGHT if "Our" in c4 or row_idx == 0 else TEXT_MUTED

    # ==========================================
    # SLIDE 11: FUTURE ROADMAP & IMPACT
    # ==========================================
    s11 = prs.slides.add_slide(blank_layout)
    set_background(s11)
    add_header(s11, "Roadmap: Scaling from Desktop to Cloud & Enterprise", "Vision & Roadmap")

    roadmap_items = [
        ("Q1 2027: Neural Video Repair", "Deep learning frame reconstruction for damaged MP4/MOV atom streams and dash-cam crash footage.", ACCENT_CYAN),
        ("Q2 2027: Cloud Blob Carving", "Extending carving algorithms to AWS S3, Azure Blob, and GCP buckets for enterprise disaster recovery.", ACCENT_PURPLE),
        ("Q3 2027: Hardware SCSI/NVMe Bypassing", "Direct firmware-level command execution to recover data directly from drives with degraded controller boards.", ACCENT_GREEN),
        ("Q4 2027: Certified Forensic Export", "Full automated compliance documentation for court-admissible digital evidence packages.", ACCENT_CYAN)
    ]

    for i, (title, desc, col) in enumerate(roadmap_items):
        cx = Inches(0.8 + i * 2.95)
        create_card(s11, cx, Inches(1.9), Inches(2.75), Inches(4.8), border_color=col)
        tb = s11.shapes.add_textbox(cx + Inches(0.2), Inches(2.2), Inches(2.35), Inches(4.2))
        tf = tb.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = title
        pt.font.size = Pt(15)
        pt.font.bold = True
        pt.font.color.rgb = col

        pd = tf.add_paragraph()
        pd.text = desc
        pd.font.size = Pt(12)
        pd.font.color.rgb = TEXT_MUTED

    # ==========================================
    # SLIDE 12: CONCLUSION & Q&A
    # ==========================================
    s12 = prs.slides.add_slide(blank_layout)
    set_background(s12)

    # Accent decorative bar
    glow12 = s12.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(2.2), Inches(0.15), Inches(3.0))
    glow12.fill.solid()
    glow12.fill.fore_color.rgb = ACCENT_GREEN
    glow12.line.fill.background()

    tb12 = s12.shapes.add_textbox(Inches(1.2), Inches(2.0), Inches(11.0), Inches(3.2))
    tf12 = tb12.text_frame
    tf12.word_wrap = True
    
    p = tf12.paragraphs[0]
    p.text = "Autonomous AI Data Recovery"
    p.font.size = Pt(36)
    p.font.bold = True
    p.font.color.rgb = TEXT_LIGHT

    p2 = tf12.add_paragraph()
    p2.text = "No File Is Ever Truly Lost."
    p2.font.size = Pt(32)
    p2.font.bold = True
    p2.font.color.rgb = ACCENT_GREEN

    p3 = tf12.add_paragraph()
    p3.text = "\nThank you for your time. Ready for Live Demonstration & Questions."
    p3.font.size = Pt(16)
    p3.font.color.rgb = TEXT_MUTED

    # Save
    prs.save(output_path)
    print(f"Presentation successfully saved to: {output_path}")

if __name__ == "__main__":
    out = os.path.abspath(r"c:\Users\adith\Desktop\Maxi\AI_Data_Recovery_Presentation.pptx")
    build_presentation(out)
