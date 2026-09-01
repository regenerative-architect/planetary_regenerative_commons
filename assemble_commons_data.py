from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_inventory import (  # noqa: E402
    classify_concepts,
    classify_domains,
    classify_layers,
    find_card,
    humanize,
    make_description,
    questions_answered,
    score_record,
    useful_auxiliary,
)


FEATURE_LABELS = {
    "gamification": "gamification",
    "zero_harm": "zero-harm framing",
    "canvas": "canvas visualization",
    "json_state": "JSON state",
    "indexeddb": "IndexedDB",
    "print_styles": "print-ready",
    "evidence_language": "evidence language",
    "offline_local_first": "local-first",
    "service_worker": "service worker",
    "tooltips_docs": "tooltips/docs",
    "sha_webcrypto": "WebCrypto/SHA-256",
    "uncertainty": "uncertainty handling",
}

PRIVATE_KEY_PATHS = {
    "global/petition/index.html",
    "global/petition/v1/index.html",
    "mycelial/strategy/bank/v1/core/index.sync.html",
    "peace/shield/index.html",
}

KNOWN_PRACTICES = {
    "agroforestry", "pollinator recovery", "watershed restoration", "food sovereignty",
    "housing dignity", "mutual aid", "climate adaptation", "citizen science",
    "evidence ledger", "de-escalation", "public infrastructure",
}

CURATED_SCORES = {
    "global/conflict/monitoring/index.html": (80, 60, 80, 60),
    "ai_targeting_incident_ledger_v1/index.html": (100, 80, 80, 60),
    "decision_atlas/index.html": (80, 80, 80, 60),
    "ai_displacement_safeguards/index.html": (60, 40, 60, 60),
    "antidisruption_regen_platform/index.html": (60, 60, 60, 60),
    "reverse_manipulation/v6/index.html": (80, 60, 80, 60),
    "benevolent_platform_architecture/index.html": (80, 80, 80, 60),
    "public_resilience/index.html": (80, 80, 80, 80),
    "biosphere_metasystems_gamified/index.html": (60, 80, 80, 60),
    "presidential_daycare_solution/index.html": (60, 40, 60, 60),
    "ai/constitution/blueprint/index.html": (80, 60, 80, 60),
    "mycelial/bank/index.html": (80, 40, 60, 60),
    "bloom_engine/index.html": (80, 40, 60, 60),
    "1001_governance_decentralization_methods/index.html": (80, 40, 60, 60),
    "toronto_edible_upgrade_v2/index.html": (80, 60, 80, 60),
}

EXPLICIT_QUESTIONS = {
    "decision_atlas/index.html": [
        "What is new in the cited research?", "What can the atlas do—and what will it not do?",
        "Who performs ecological work, and what can institutions actually do?",
    ],
    "ai_targeting_incident_ledger_v1/index.html": [
        "Am I being targeted?", "Is this algorithmic or human?", "What evidence would change confidence?",
        "What should I secure first?",
    ],
    "global/conflict/monitoring/index.html": [
        "Are sources independent or echoing one another?", "What evidence threshold fits the reversibility of an action?",
        "How could an adversary game the method?",
    ],
    "public_resilience/index.html": [
        "Why treat edible perennial landscapes as public infrastructure?", "What does current public evidence support?",
        "How can a government move from brief to bounded pilot?",
    ],
    "toronto_edible_upgrade_v2/index.html": [
        "Which sites are candidates?", "Which sites require a food-safety gate?", "What are the next steps?",
    ],
    "benevolent_platform_architecture/index.html": [
        "Who is this architecture for?", "What threat classes is it designed against?", "Which modules are complete or missing?",
    ],
    "reverse_manipulation/v6/index.html": [
        "How can people recognize manipulation without building counter-propaganda?", "What conditions support recovery?",
        "What should educators, institutions, and communities do?",
    ],
    "antidisruption_regen_platform/index.html": [
        "Which sectors and tasks appear exposed?", "Which institutions are stressed?", "Which early warnings should trigger review?",
    ],
    "presidential_daycare_solution/index.html": [
        "What is the four-move childcare cascade?", "How can research become operating rules?", "Which pilots are bounded and replicable?",
    ],
    "africa_hydrospheric_cascade_initiative/index.html": [
        "Which hydrological processes matter?", "Which governance tier owns which role?", "What requires local data?",
    ],
    "biosphere_metasystems_gamified/index.html": [
        "What is known, piloting, or guessed?", "Which experiments remain?", "How does the project defend against inversion?",
    ],
    "1001_governance_decentralization_methods/index.html": [
        "Which transparency and participation methods fit a context?", "What belongs in a transformation roadmap and policy brief?",
    ],
}


def path_quarantine_reason(rel: str, generated_or_internal: bool = False) -> str | None:
    low = rel.replace("\\", "/").lower()
    parts = low.split("/")
    if low.startswith("aifinalwarning-chatgpt-history/"):
        return "private history/media export"
    if low.startswith("ref/dataset/gpt/trf/"):
        return "credential-like dataset"
    if rel in PRIVATE_KEY_PATHS or low in PRIVATE_KEY_PATHS:
        return "private-key signature"
    if ".git" in parts or ".github" in parts or generated_or_internal:
        return "repository/build internals"
    if low.startswith("logs/") or low.endswith("/traffic.db") or low == "logs/traffic.db":
        return "operational logs"
    if (
        low.startswith(("corruption/", "proof/", "comms/can/gov/secure/", "stateofaffairspublicnotice/"))
        or "/corruption/" in f"/{low}"
        or low.startswith("corruption+")
        or "publicnotice" in low
    ):
        return "sensitive civic/legal allegations"
    if any(part in {".env", "credentials", "secrets", "private_keys"} for part in parts):
        return "secret/config material"
    return None


def contains_secret_signature(data: bytes) -> bool:
    sample = data[:2_000_000]
    patterns = [
        rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
        rb"\bghp_[A-Za-z0-9]{30,}\b",
        rb"\bgithub_pat_[A-Za-z0-9_]{30,}\b",
    ]
    return any(re.search(pattern, sample) for pattern in patterns)


def strip_visible_html(text: str) -> str:
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    text = re.sub(r"<(?:script|style|template|svg)\b.*?</(?:script|style|template|svg)\s*>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&(?:nbsp|amp|quot|apos|lt|gt);", " ", text, flags=re.I)
    return re.sub(r"\s+", " ", text).strip()


def safe_read(corpus: Path, archive_path: Path, rel: str) -> bytes:
    path = corpus / Path(rel)
    if path.exists():
        return path.read_bytes()
    with zipfile.ZipFile(archive_path) as zf:
        return zf.read(rel)


def knowledge_status_for(signal: str, layer: str, concepts: list[str]) -> str:
    low = signal.lower()
    if re.search(r"speculative|science fiction|far future|quantum|galactic|cosmic|mythic|unverified mechanism", low):
        return "speculative concept"
    if re.search(r"hypothesis|research question|proposed mechanism|needs? validation|theoretical|research agenda", low):
        return "hypothesis"
    if layer in {"pattern", "concept", "deployment"} and any(concept in KNOWN_PRACTICES for concept in concepts):
        return "established idea"
    return "integration"


def build_status_for(rel: str, signal: str, features: list[str], scores: dict[str, int]) -> str | None:
    if rel.lower() == "public_resilience/index.html" and scores["maturity"] >= 60 and scores["safety"] >= 60:
        return "field-test candidate"
    interactive = {"IndexedDB", "JSON state", "canvas visualization", "service worker", "gamification"}
    if interactive.intersection(features) or re.search(r"prototype|proof of concept|\bpoc\b|experimental|demo\b|simulator|game\b", signal, re.I):
        return "experimental prototype"
    return None


def nearest_license(rel: str, license_rows: list[dict]) -> str:
    low = rel.lower()
    if low == "education2" or low.startswith("education2/"):
        return "conflicting terms / legal review required"
    best = None
    for item in license_rows:
        prefix = item["path"].replace("\\", "/").rsplit("/", 1)[0].lower()
        if prefix and (low == prefix or low.startswith(prefix + "/")):
            candidate = (len(prefix), item["detected_license"])
            if best is None or candidate[0] > best[0]:
                best = candidate
    return best[1] if best else "not located / unclear"


def build_recipes(cards: list[dict]) -> list[dict]:
    specs = [
        {
            "id": "conflict_evidence_loop",
            "title": "Conflict-safe evidence loop",
            "outcome": "Separate observation from interpretation, corroborate claims, and route high-risk signals toward reversible de-escalation.",
            "selectors": [("global/conflict/monitoring",), ("ai_targeting_incident_ledger",), ("conflict_deescalation",), ("reverse_manipulation",)],
            "steps": ["Log observations and source independence", "Score uncertainty and alternatives", "Trigger human review thresholds", "Choose reversible de-escalation actions"],
            "safetyGate": "No attribution or intervention without corroboration, proportionality, and accountable human review.",
            "evidenceGate": "Preserve raw observations, timestamps, dissenting interpretations, and confidence changes."
        },
        {
            "id": "ai_transition_safety_stack",
            "title": "AI transition safety stack",
            "outcome": "Connect disruption scenarios to a large safeguard library and monitored institutional responses.",
            "selectors": [("antidisruption_regen_platform",), ("ai_displacement_safeguards",), ("job_displacement_safeguards",), ("ai_disruption_safeguards",)],
            "steps": ["Model a disruption scenario", "Identify vulnerable groups and institutions", "Match safeguards to failure modes", "Monitor distributional outcomes and revise"],
            "safetyGate": "Do not automate eligibility, punishment, or livelihood decisions; preserve appeal and human override paths.",
            "evidenceGate": "Validate assumptions against labor data, lived experience, distributional impacts, and counterfactuals."
        },
        {
            "id": "biosphere_operations_pilot",
            "title": "Biosphere operations pilot",
            "outcome": "Join ecological sensing, restoration choices, community governance, and impact tracking in one bounded pilot.",
            "selectors": [("decision_atlas",), ("biosphere",), ("cascade_commons",), ("impacttracker",)],
            "steps": ["Define one ecological boundary", "Establish baseline data and uncertainty", "Co-design reversible interventions", "Publish outcomes and side effects"],
            "safetyGate": "Require ecological review, local consent, stop conditions, and monitoring before field intervention.",
            "evidenceGate": "Use baseline/control comparisons and report null or adverse outcomes alongside successes."
        },
        {
            "id": "edible_resilience_district",
            "title": "Edible resilience district",
            "outcome": "Combine public food infrastructure, canopy, water, and pollinator modules into a municipal test.",
            "selectors": [("public_resilience",), ("toronto_edible_upgrade",), ("global_pollinator",), ("africa_hydrospheric",)],
            "steps": ["Map public assets and community priorities", "Select climate-appropriate perennial species", "Integrate water and pollinator corridors", "Assign maintenance and access governance"],
            "safetyGate": "Screen species, allergens, contamination, accessibility, Indigenous rights, and long-term maintenance.",
            "evidenceGate": "Track survival, food access, biodiversity, heat, runoff, maintenance cost, and community feedback."
        },
        {
            "id": "housing_dignity_pathway",
            "title": "Housing dignity pathway",
            "outcome": "Connect immediate shelter, decentralized accountability, food security, and long-term community support.",
            "selectors": [("canada_zero_homelessness",), ("decentralized_homelessness",), ("child_hunger",), ("public_resilience",)],
            "steps": ["Start with unconditional safety and housing", "Offer voluntary support", "Link food and community resources", "Let affected people govern success criteria"],
            "safetyGate": "No surveillance, forced treatment, punitive scoring, or loss of services for nonparticipation.",
            "evidenceGate": "Measure housing stability, wellbeing, access, user-defined outcomes, and unintended exclusion."
        },
        {
            "id": "youth_agency_commons",
            "title": "Youth agency commons",
            "outcome": "Pair anti-manipulation safeguards with child-centered participation, local data, and incident learning.",
            "selectors": [("reverse_manipulation",), ("protecting_children_with_ai",), ("digital/democracy/portal",), ("ai_targeting_incident_ledger",)],
            "steps": ["Define rights and consent boundaries", "Map manipulation without profiling children", "Provide local-first reporting and learning", "Escalate through accountable humans"],
            "safetyGate": "Child rights, data minimization, advocate review, and non-retaliation are mandatory.",
            "evidenceGate": "Distinguish observed harms from inferred intent and use age-appropriate participatory evaluation."
        },
        {
            "id": "reef_to_watershed_recovery",
            "title": "Reef-to-watershed recovery",
            "outcome": "Connect upstream pollution prevention, river restoration, coastal habitat recovery, and shared governance.",
            "selectors": [("coral_reef_governance",), ("reversing_coral_damage",), ("river_restoration",), ("river_pollution_prevention",)],
            "steps": ["Map upstream-downstream pressures", "Set ecological and community baselines", "Sequence least-regret interventions", "Share monitoring and governance"],
            "safetyGate": "Avoid untested biological releases or irreversible geoengineering; use independent ecological review.",
            "evidenceGate": "Track water quality, habitat response, spillovers, maintenance, and community-defined benefits."
        },
    ]
    output = []
    for spec in specs:
        component_ids = []
        for terms in spec.pop("selectors"):
            card = find_card(cards, *terms)
            if card and card["id"] not in component_ids:
                component_ids.append(card["id"])
        if len(component_ids) < 2:
            continue
        selected = [next(card for card in cards if card["id"] == cid) for cid in component_ids]
        output.append({
            **spec,
            "componentIds": component_ids,
            "compatibility": round(sum(card["scores"]["compatibility"] for card in selected) / len(selected)),
        })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    summary = json.loads((args.inventory / "archive_summary.json").read_text(encoding="utf-8"))
    canonicals = json.loads((args.inventory / "canonical_html_builds.json").read_text(encoding="utf-8"))
    families = json.loads((args.inventory / "html_version_families.json").read_text(encoding="utf-8"))
    license_rows = json.loads((args.inventory / "license_candidates.json").read_text(encoding="utf-8"))
    family_by_key = {item["family_key"]: item for item in families}
    archive_path = Path(summary["archive"]["path"])

    quarantine_counts: Counter[str] = Counter()
    entries = []
    with (args.inventory / "entries.csv").open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["is_directory"].lower() == "true":
                continue
            generated = row["generated_or_internal"].lower() == "true"
            reason = path_quarantine_reason(row["path"], generated)
            if reason:
                quarantine_counts[reason] += 1
            row["quarantine_reason"] = reason
            entries.append(row)

    cards = []
    secret_family_count = 0
    for canonical in canonicals:
        family = family_by_key[canonical["family_key"]]
        public_variants = [
            variant for variant in family["variants"]
            if not path_quarantine_reason(variant["path"])
        ]
        if not public_variants:
            continue
        canonical_variant = next((variant for variant in public_variants if variant.get("is_canonical")), public_variants[0])
        rel = canonical_variant["path"]
        raw = safe_read(args.corpus, archive_path, rel)
        if contains_secret_signature(raw) or rel in PRIVATE_KEY_PATHS:
            secret_family_count += 1
            continue
        text = raw[:400_000].decode("utf-8", errors="replace")
        visible = strip_visible_html(text)[:110_000]
        title = re.sub(r"[\x00-\x1f\x7f]", " ", canonical.get("title") or family.get("display_title") or humanize(Path(rel).stem))
        title = re.sub(r"\s+", " ", title).strip()[:180]
        if re.search(r"genocide|complicity report|audit claims|fact-check:|criminal allegation|evidence against", title, re.I):
            quarantine_counts["sensitive civic/legal allegations"] += len(public_variants)
            continue
        signal = f"{title} {rel} {visible}"
        domains = classify_domains(signal)
        concepts = classify_concepts(signal, domains)
        primary_layer, layers = classify_layers(signal, rel, ".html")
        agent_layers = [layer for layer in canonical.get("layers", []) if layer in {"concept", "module", "pattern", "system", "deployment", "dataset", "research", "safety", "innovation"}]
        layers = list(dict.fromkeys([primary_layer, *layers, *agent_layers]))
        features = [FEATURE_LABELS[key] for key, enabled in canonical["features"].items() if enabled and key in FEATURE_LABELS]
        scores = score_record(text, int(canonical_variant["size"]), features)
        score_origin = "heuristic"
        if rel.lower() in CURATED_SCORES:
            c, e, s, m = CURATED_SCORES[rel.lower()]
            scores = {"compatibility": c, "evidence": e, "safety": s, "maturity": m}
            score_origin = "curator-reviewed rubric"
        knowledge_status = knowledge_status_for(signal, primary_layer, concepts)
        build_status = build_status_for(rel, signal, features, scores)
        statuses = [knowledge_status] + ([build_status] if build_status else [])
        explicit_questions = EXPLICIT_QUESTIONS.get(rel.lower())
        if explicit_questions:
            question_metadata = [{"text": question, "basis": "explicit or directly grounded"} for question in explicit_questions]
        else:
            question_metadata = [{"text": question, "basis": "curator synthesized"} for question in questions_answered(visible, features, layers, concepts)]
        card_id = "psc_" + hashlib.sha1(canonical["family_key"].encode()).hexdigest()[:11]
        cards.append({
            "id": card_id,
            "title": title,
            "description": make_description(title, primary_layer, domains, concepts),
            "path": rel,
            "domain": domains[0],
            "domains": domains,
            "layer": primary_layer,
            "layers": layers,
            "status": knowledge_status,
            "knowledgeStatus": knowledge_status,
            "buildStatus": build_status,
            "statuses": statuses,
            "concepts": concepts,
            "features": features,
            "questions": question_metadata,
            "scores": scores,
            "scoreOrigin": score_origin,
            "license": nearest_license(rel, license_rows),
            "provenance": {
                "sha256": canonical_variant["sha256"],
                "sizeBytes": int(canonical_variant["size"]),
                "familyStatus": family["status"],
                "groupingConfidence": family["grouping_confidence"],
                "groupingReason": family["grouping_reason"],
                "familyFiles": len(public_variants),
                "distinctBuilds": len({variant["sha256"] for variant in public_variants}),
                "aliases": [variant["path"] for variant in public_variants[:20]],
                "versions": [
                    {"path": variant["path"], "sha256": variant["sha256"], "size": int(variant["size"]), "words": int(variant.get("word_count", 0))}
                    for variant in public_variants[:12]
                ],
            },
        })

    cards.sort(key=lambda card: (-(card["scores"]["maturity"] + card["scores"]["evidence"] + card["scores"]["safety"]), card["title"].lower()))

    public_groups = defaultdict(list)
    for row in entries:
        if row["quarantine_reason"]:
            continue
        public_groups[row["sha256"]].append(row)

    auxiliary_candidates = []
    for digest, group in public_groups.items():
        rep = min(group, key=lambda row: (len(row["path"]), row["path"].lower()))
        aliases = sorted(row["path"] for row in group)
        score = useful_auxiliary(rep["path"], rep["extension"])
        if score > 2 and rep["extension"] in {".md", ".json", ".csv", ".tsv", ".geojson", ".pdf", ".xlsx", ".bib"}:
            auxiliary_candidates.append((score, digest, rep, group))
    auxiliaries = []
    for score, digest, rep, group in sorted(auxiliary_candidates, key=lambda item: (-item[0], item[2]["path"].lower()))[:500]:
        title = humanize(Path(rep["path"]).name if Path(rep["path"]).stem.lower() != "readme" else Path(rep["path"]).parent.name)
        signal = f"{title} {rep['path']}"
        domains = classify_domains(signal)
        concepts = classify_concepts(signal, domains)
        layer, layers = classify_layers(signal, rep["path"], rep["extension"])
        if rep["extension"] in {".csv", ".tsv", ".json", ".geojson", ".xlsx"} and "dataset" not in layers:
            layer, layers = "dataset", ["dataset", *layers]
        auxiliaries.append({
            "id": "aux_" + digest[:11],
            "title": title,
            "path": rep["path"],
            "extension": rep["extension"] or "[no extension]",
            "sizeBytes": int(rep["size"]),
            "copies": len(group),
            "sha256": digest,
            "domain": domains[0],
            "layer": layer,
            "layers": layers,
            "concepts": concepts[:6],
            "description": make_description(title, layer, domains, concepts),
            "license": nearest_license(rep["path"], license_rows),
        })

    indexed_records = []
    for card in cards:
        indexed_records.append({
            "path": card["path"], "extension": ".html", "category": "version-collapsed HTML family",
            "sizeBytes": card["provenance"]["sizeBytes"], "sha256": card["provenance"]["sha256"][:16],
            "copies": card["provenance"]["familyFiles"], "aliases": card["provenance"]["aliases"][:8],
        })
    for record in auxiliaries:
        indexed_records.append({
            "path": record["path"], "extension": record["extension"], "category": f"{record['layer']} metadata record",
            "sizeBytes": record["sizeBytes"], "sha256": record["sha256"][:16],
            "copies": record["copies"], "aliases": [record["path"]],
        })
    raw_inventory = sorted(indexed_records, key=lambda row: (row["extension"], row["path"].lower()))

    public_extension_counts = Counter()
    public_category_counts = Counter()
    for row in entries:
        if not row["quarantine_reason"]:
            public_extension_counts[row["extension"] or "[none]"] += 1
            public_category_counts[row["category"]] += 1

    feature_counts = Counter(feature for card in cards for feature in card["features"])
    domain_counts = Counter(card["domain"] for card in cards)
    layer_counts = Counter(card["layer"] for card in cards)
    status_counts = Counter(status for card in cards for status in card["statuses"])
    knowledge_status_counts = Counter(card["knowledgeStatus"] for card in cards)
    build_status_counts = Counter(card["buildStatus"] for card in cards if card["buildStatus"])
    license_counts = Counter(row["detected_license"] for row in license_rows)
    quarantine_counts["credential/private-key signatures"] += secret_family_count

    source = summary["archive"]
    html_summary = summary["html_inventory"]
    data = {
        "schemaVersion": "1.0.0",
        "generated": "2026-08-31",
        "source": {
            "archiveName": "download.zip",
            "archiveSha256": source["sha256"],
            "compressedBytes": source["bytes"],
            "uncompressedBytes": source["uncompressed_file_bytes"],
            "zipEntries": source["zip_entry_count"],
            "method": "Definitive SHA-256 deduplication, normalized-visible-text comparison, then conservative title/path version families with every public variant retained.",
        },
        "metrics": {
            "actualFiles": source["file_count"],
            "directoryEntries": source["directory_entry_count"],
            "exactDistinctFiles": summary["outer_file_inventory"]["distinct_sha256_count_including_empty"],
            "curatedFiles": summary["outer_file_inventory"]["curated_file_count_excluding_generated_or_internal"],
            "curatedDistinctFiles": summary["outer_file_inventory"]["curated_distinct_sha256_count_including_empty"],
            "htmlFiles": html_summary["html_file_count"],
            "distinctHtmlBuilds": html_summary["byte_distinct_html_build_count"],
            "normalizedTextBuilds": html_summary["normalized_visible_text_distinct_count"],
            "versionFamilies": html_summary["version_family_count"],
            "publicCatalogFamilies": len(cards),
            "researchDatasetRecords": len(auxiliaries),
            "quarantinedFiles": sum(quarantine_counts.values()),
            "nestedZipContainers": summary["nested_zip_inventory"]["container_count"],
        },
        "extensionCounts": [{"extension": key, "count": value} for key, value in public_extension_counts.most_common()],
        "categoryCounts": [{"name": key, "count": value} for key, value in public_category_counts.most_common()],
        "featureCounts": [{"feature": key, "count": value, "percent": round(value * 100 / max(1, len(cards)), 1)} for key, value in feature_counts.most_common()],
        "domainCounts": [{"name": key, "count": value} for key, value in domain_counts.most_common()],
        "layerCounts": [{"name": key, "count": value} for key, value in layer_counts.most_common()],
        "statusCounts": [{"name": key, "count": value} for key, value in status_counts.most_common()],
        "knowledgeStatusCounts": [{"name": key, "count": value} for key, value in knowledge_status_counts.most_common()],
        "buildStatusCounts": [{"name": key, "count": value} for key, value in build_status_counts.most_common()],
        "quarantineSummary": [{"reason": key, "count": value} for key, value in quarantine_counts.most_common()],
        "licenseSummary": [{"name": key, "count": value} for key, value in license_counts.most_common()],
        "familyMethod": {
            "statuses": summary["html_inventory"]["family_status_counts"],
            "note": summary["html_inventory"]["method_note"],
        },
        "definitions": {
            "statuses": {
                "established idea": "Uses practices with an existing real-world evidence base; this archive instance is still not independently validated.",
                "integration": "Combines known ideas or components in a distinctive architecture; integration value is plausible, not proven.",
                "hypothesis": "Makes a testable proposition requiring evidence, falsification criteria, and independent review.",
                "experimental prototype": "An interactive or technical demonstration suitable for controlled evaluation, not operational reliance.",
                "field-test candidate": "Structured enough for an ethics-reviewed, bounded, reversible pilot with monitoring and stop conditions.",
                "speculative concept": "Exploratory future-facing idea whose mechanism, feasibility, or impact is substantially unverified.",
            },
            "layers": {
                "concept": "A portable idea or framing.",
                "module": "A reusable functional component with a recognizable input/output role.",
                "pattern": "A repeatable way to combine modules or organize work.",
                "system": "A larger architecture coordinating multiple modules and stakeholders.",
                "deployment": "A place- or problem-specific application candidate.",
                "dataset": "Structured records, registries, manifests, or measurements.",
                "research": "Methods, papers, evidence reviews, or testable research directions.",
                "safety": "Safeguards, risk controls, incident learning, or zero-harm constraints.",
                "innovation": "Novel or experimental mechanisms and invention hypotheses.",
            },
            "scores": {
                "compatibility": "Interface-readiness estimate from local operation, structured data, modular language, accessibility, and external dependencies.",
                "evidence": "Documentation signal from sources, methodology, uncertainty, corroboration, and validation language—not an appraisal of evidence quality.",
                "safety": "Presence of safeguards, consent, privacy, uncertainty, reversibility, auditability, and zero-harm language—not a safety certification.",
                "maturity": "Artifact completeness signal from interaction, persistence, documentation, accessibility, and export/print support—not field readiness.",
            },
        },
        "licenses": {
            "candidateCount": len(license_rows),
            "notice": "Licenses are heterogeneous and detection is heuristic. No source code or assets are embedded. The most specific source license controls; absence of a license is not permission.",
        },
        "privacy": {
            "notice": "Potential credentials, private keys, personal exports/media, operational logs, and repository internals were quarantined. Only aggregate counts are retained; raw source files are not redistributed.",
        },
        "cards": cards,
        "auxiliaries": auxiliaries,
        "rawInventory": raw_inventory,
        "recipes": build_recipes(cards),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "bytes": args.output.stat().st_size,
        "metrics": data["metrics"],
        "statuses": data["statusCounts"],
        "recipes": [{"title": r["title"], "components": len(r["componentIds"])} for r in data["recipes"]],
        "quarantine": data["quarantineSummary"],
    }, indent=2))


if __name__ == "__main__":
    main()
