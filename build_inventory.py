from __future__ import annotations

import argparse
import hashlib
import html as html_lib
import json
import math
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


ARCHIVE_SHA256 = "F142C1C77CFE2209A18105479D34FF0F619141B2D44ADF60E3EC4C2B29346DAF"
ARCHIVE_BYTES = 219_897_626
ZIP_ENTRIES = 7_204

FEATURE_PATTERNS = {
    "gamification": r"\b(?:quest|quests|xp|badge|badges|leaderboard|gamif|achievement)\b",
    "zero-harm framing": r"zero[\s-]?harm|do no harm|non[\s-]?harm|harm minim",
    "canvas visualization": r"<canvas\b|getcontext\s*\(",
    "JSON state": r"json\.(?:parse|stringify)|application/json|\bjson\b",
    "IndexedDB": r"indexeddb|idb(?:database|request)?\b",
    "print-ready": r"@media\s+print|window\.print\s*\(",
    "evidence language": r"\b(?:evidence|citation|citations|sources?|references?|peer[\s-]?reviewed|doi)\b",
    "local-first": r"local[\s-]?first|offline[\s-]?first|works? offline|device[\s-]?local",
    "service worker": r"serviceworker|service[\s-]?worker|navigator\.serviceworker",
    "tooltips/docs": r"\btooltip\b|aria-describedby|<details\b|documentation|\bhelp\b",
    "WebCrypto/SHA-256": r"sha[\s-]?256|subtle\.digest|webcrypto",
    "uncertainty handling": r"\buncertain(?:ty)?\b|confidence interval|unknown\b|epistemic|confidence score",
    "import/export": r"\b(?:import|export)\b.{0,80}\b(?:json|csv|data|file)\b|download\s*=|filereader",
    "accessibility": r"aria-label|aria-labelledby|role=|skip[\s-]?link|prefers-reduced-motion",
}

DOMAIN_PATTERNS = {
    "biosphere & ecology": r"biospher|ecosystem|ecolog|biodivers|forest|coral|reef|species|wildlife|habitat|reforestation|mycel|soil|canopy|trophic",
    "water & oceans": r"\bwater\b|hydro|watershed|rainwater|desalin|aquatic|river|ocean|marine|seagrass|flood|wetland",
    "food & agriculture": r"\bfood\b|agro|farm|edible|hunger|pollinat|\bbee|garden|seed|orchard|agricultur",
    "governance & civic systems": r"govern|civic|democra|voting|\bdao\b|decentral|policy|institution|accountab|corruption|council|public administration",
    "peace & human security": r"\bpeace|conflict|de[\s-]?escal|weapon|\bwar\b|crisis|safety|safeguard|sentinel|threat|fraud|security",
    "AI & digital agency": r"artificial intelligence|\bai\b|algorithm|digital|cyber|data sovereign|software|offline|internet|cognitive|manipulation|platform",
    "housing & social care": r"housing|homeless|shelter|childcare|poverty|inequal|community care|social care|daycare",
    "economy & workforce": r"career|\bjob|workforce|econom|\btax|wealth|financ|trade|employment|income|labor|livelihood",
    "education & culture": r"educat|learning|teacher|school|story|media|culture|hollywood|game|literacy|narrative",
    "health & biosafety": r"health|biosecurity|biosafety|medical|drug|oral|pheromone|wellbeing|mental health|public health",
    "climate & infrastructure": r"climate|atmospher|energy|infrastructure|building|transport|wildfire|fire prevention|resilien|urban|city|grid",
    "research & evidence": r"research|evidence|science|epistem|ledger|provenance|monitoring|study|methodology|experiment",
}

CONCEPT_PATTERNS = {
    "local-first": r"local[\s-]?first|offline[\s-]?first|works? offline",
    "provenance": r"provenance|chain of custody|source ledger",
    "uncertainty": r"uncertain(?:ty)?|confidence interval|epistemic|unknown\b",
    "evidence ledger": r"evidence ledger|incident ledger|claim ledger|evidence grade",
    "zero-harm": r"zero[\s-]?harm|do no harm|non[\s-]?harm",
    "consent": r"\bconsent|opt[\s-]?in|permission",
    "decentralization": r"decentrali|distributed governance|townless",
    "participation": r"participat|co[\s-]?design|deliberat|citizen assembly",
    "accountability": r"accountab|anti[\s-]?corruption|auditab",
    "risk & safeguards": r"risk matrix|safeguard|safety gate|hazard|risk register",
    "resilience": r"resilien|continuity|shock absorb|anti[\s-]?collapse",
    "biosphere operations": r"biosphere|ecological operation|ecosystem coordination",
    "watershed restoration": r"watershed|river restoration|hydrospheric cascade",
    "water sovereignty": r"water sovereign|community water|water security",
    "food sovereignty": r"food sovereign|food security|local food",
    "agroforestry": r"agroforest|food forest|silvopast",
    "pollinator recovery": r"pollinat|bee habitat|avian|bird friendly",
    "biodiversity": r"biodivers|multispecies|species recovery|habitat",
    "planetary restoration": r"planetary restoration|regenerat|ecological repair",
    "circular economy": r"circular econom|waste[\s-]?to[\s-]?resource|closed loop",
    "workforce transition": r"workforce transition|regenerative career|job displacement|successor role|reskilling",
    "economic justice": r"economic justice|wealth distribut|inequal|fiscal inversion|tax reduction",
    "housing dignity": r"homeless|housing|shelter|housing dignity",
    "child wellbeing": r"child|youth|daycare|childcare|kid safety",
    "learning systems": r"education|learning|teacher|literacy|curriculum",
    "cognitive autonomy": r"cognitive autonom|manipulation|agency garden|attention system",
    "AI safety": r"ai safety|benevolent ai|alignment|algorithmic harm|ai targeting",
    "de-escalation": r"de[\s-]?escal|conflict prevention|peace pathway",
    "peace informatics": r"peace informatic|conflict monitor|epistemology.{0,30}peace",
    "scenario modeling": r"scenario|simulat|stress test|what[\s-]?if",
    "impact measurement": r"impact measur|impact tracker|outcome monitor|metrics dashboard",
    "gamified learning": r"gamif|\bquest|\bxp\b|badge|leaderboard",
    "offline distribution": r"offline|single[\s-]?file|ipfs|liveusb|mesh network",
    "cryptographic integrity": r"sha[\s-]?256|webcrypto|content hash|tamper",
    "public infrastructure": r"public infrastructure|public asset|municipal|institutional os",
    "urban systems": r"urban|\bcity|toronto|ottawa|montreal|capital resilience",
    "data sovereignty": r"data sovereign|local data|privacy by design|device local",
    "field pilots": r"field test|pilot|deployment candidate|prototype deployment",
    "mutual aid": r"mutual aid|solidarity|reciprocity|community support",
    "Indigenous stewardship": r"indigenous|traditional ecological knowledge|first nations",
    "multispecies governance": r"multispecies|species representation|avian governance",
    "regenerative finance": r"regenerative finance|impact invest|carbon credit|debt[\s-]?to[\s-]?soil",
    "emergency response": r"emergency response|crisis response|disaster|relief",
    "climate adaptation": r"climate adapt|heat resilience|flood resilience|wildfire",
    "citizen science": r"citizen science|community monitoring|participatory research",
    "open knowledge": r"open knowledge|open source|commons|public domain|knowledge graph",
}

GENERIC_TITLES = {
    "index", "home", "dashboard", "portal", "app", "application", "untitled", "project",
    "planetary restoration portal", "planetary restoration", "foster navi", "main",
}

PLACE_TERMS = re.compile(
    r"\b(?:toronto|ottawa|montreal|alberta|canada|africa|afghanistan|bangladesh|china|gaza|honduras|"
    r"india|indonesia|iran|japan|korea|lebanon|morocco|newfoundland|pakistan|russia|uae|usa|america|"
    r"st\.? john'?s|fort mcmurray|global|south america|north america)\b",
    re.I,
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_text(path: Path, limit: int | None = None) -> str:
    data = path.read_bytes()
    if limit is not None:
        data = data[:limit]
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def clean_space(value: str) -> str:
    value = html_lib.unescape(value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def extract_title(text: str, fallback: str) -> str:
    match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", text, re.I | re.S)
    if match:
        title = clean_space(match.group(1))
        if title:
            return title[:180]
    match = re.search(r"<h1\b[^>]*>(.*?)</h1\s*>", text, re.I | re.S)
    if match:
        title = clean_space(match.group(1))
        if title:
            return title[:180]
    return humanize(fallback)[:180]


def humanize(value: str) -> str:
    value = re.sub(r"\.(?:html?|md|json|csv|pdf)$", "", value, flags=re.I)
    value = re.sub(r"(?:^|[_\-])v(?:ersion)?[_\-]?\d+(?=$|[_\-])", " ", value, flags=re.I)
    value = re.sub(r"[_\-]+", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value.title() if value else "Untitled archive artifact"


def normalize_key(value: str) -> str:
    value = html_lib.unescape(value).lower()
    value = re.sub(r"[\U00010000-\U0010ffff]", " ", value)
    value = re.sub(r"\b(?:version|ver|v)\s*[._-]?\s*\d+(?:\.\d+)*\b", " ", value)
    value = re.sub(r"\b(?:20\d{2})[-_]?\d{2}[-_]?\d{2}(?:[-_]?\d{4,6})?\b", " ", value)
    value = re.sub(r"\b(?:final|latest|updated|revised|copy|alt|new)\b", " ", value)
    value = re.sub(r"\bindex\s*\d*\b", " ", value)
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def path_anchor(rel: str) -> str:
    p = PurePosixPath(rel)
    stem = p.stem
    segments = list(p.parts[:-1])
    if re.fullmatch(r"(?:index|home|main|default)\s*(?:v?\d+)?", stem, re.I):
        while segments and re.fullmatch(r"v(?:ersion)?\d+|\d{8}(?:-\d{6})?", segments[-1], re.I):
            segments.pop()
        stem = segments[-1] if segments else stem
    key = normalize_key(stem)
    if key in GENERIC_TITLES or len(key) < 4:
        meaningful = [normalize_key(x) for x in segments if normalize_key(x) not in GENERIC_TITLES]
        key = meaningful[-1] if meaningful else key
    return key


def title_key(title: str) -> str:
    title = re.split(r"\s+[|·•]\s+", title)[0]
    title = re.sub(r"\s+[—–-]\s+(?:foster|navi|dashboard|portal|platform|prototype)\b.*$", "", title, flags=re.I)
    return normalize_key(title)


def explicit_version(rel: str) -> int:
    values = []
    for pattern in (
        r"(?:^|[/_\-.])v(?:ersion)?[_\-.]?(\d+)(?=$|[/_\-.])",
        r"(?:^|/)index[_\-.]?(\d+)\.html$",
    ):
        values.extend(int(v) for v in re.findall(pattern, rel.lower()))
    return max(values, default=0)


def pattern_score(pattern: str, haystack: str) -> int:
    return len(re.findall(pattern, haystack, re.I))


def classify_domains(haystack: str) -> list[str]:
    scored = [(pattern_score(pattern, haystack), name) for name, pattern in DOMAIN_PATTERNS.items()]
    scored = sorted((score, name) for score, name in scored if score > 0)[::-1]
    if not scored:
        return ["cross-domain systems"]
    ceiling = scored[0][0]
    return [name for score, name in scored if score >= max(1, ceiling * 0.28)][:3]


def classify_concepts(haystack: str, domains: list[str]) -> list[str]:
    scored = [(pattern_score(pattern, haystack), name) for name, pattern in CONCEPT_PATTERNS.items()]
    scored = sorted((score, name) for score, name in scored if score > 0)[::-1]
    concepts = [name for _, name in scored[:8]]
    if not concepts:
        concepts = [domains[0]]
    return concepts


def detect_features(text: str) -> list[str]:
    return [name for name, pattern in FEATURE_PATTERNS.items() if re.search(pattern, text, re.I | re.S)]


def classify_layers(haystack: str, rel: str, ext: str) -> tuple[str, list[str]]:
    layers: list[str] = []
    if ext in {".csv", ".tsv", ".json", ".geojson"} and re.search(r"data|dataset|registry|catalog|ledger|manifest|metric|evidence", haystack, re.I):
        layers.append("dataset")
    if re.search(r"research|paper|study|methodology|evidence review|literature|experiment|epistem", haystack, re.I):
        layers.append("research")
    if re.search(r"zero[\s-]?harm|safety|safeguard|risk|de[\s-]?escal|conflict|incident ledger|biosecurity|biosafety", haystack, re.I):
        layers.append("safety")
    if re.search(r"innovation|prototype|novel|invention|experimental|blueprint", haystack, re.I):
        layers.append("innovation")
    if PLACE_TERMS.search(haystack) and re.search(r"deploy|pilot|city|regional|national|initiative|local", haystack, re.I):
        layers.append("deployment")
    if re.search(r"\b(?:system|platform|operating system|\bos\b|initiative|atlas|network|commons|hub|portal|architecture)\b", haystack, re.I):
        layers.append("system")
    if re.search(r"\b(?:engine|ledger|dashboard|mapper|calculator|toolkit|tool|registry|simulator|console|monitor)\b", haystack, re.I):
        layers.append("module")
    if re.search(r"\b(?:framework|protocol|model|bridge|method|pattern|template|guide|playbook)\b", haystack, re.I):
        layers.append("pattern")
    if not layers:
        layers.append("concept")
    primary_order = ["dataset", "research", "deployment", "system", "module", "pattern", "safety", "innovation", "concept"]
    primary = next(layer for layer in primary_order if layer in layers)
    ordered = [primary] + [x for x in layers if x != primary]
    return primary, ordered


def score_record(text: str, size: int, features: list[str], status_hint: str | None = None) -> dict[str, int]:
    low = text.lower()
    url_count = len(re.findall(r"https?://", low))
    evidence = 10
    evidence += 9 if "evidence language" in features else 0
    evidence += 8 if re.search(r"\b(?:references|bibliography|sources|citations)\b", low) else 0
    evidence += min(18, url_count)
    evidence += 10 if re.search(r"\bdoi\b|peer[\s-]?review", low) else 0
    evidence += 8 if "uncertainty handling" in features else 0
    evidence += 7 if re.search(r"methodolog|validation|falsifi|baseline|corrobor", low) else 0
    evidence = min(94, evidence)

    safety = 24
    safety += 15 if "zero-harm framing" in features else 0
    safety += 10 if re.search(r"safety|safeguard|risk register|hazard", low) else 0
    safety += 8 if re.search(r"\bconsent|opt[\s-]?in", low) else 0
    safety += 7 if re.search(r"privacy|data minim|device[\s-]?local", low) else 0
    safety += 8 if "uncertainty handling" in features else 0
    safety += 7 if re.search(r"rollback|reversible|human review|red team", low) else 0
    safety += 6 if re.search(r"auditab|provenance", low) else 0
    safety = min(96, safety)

    external_runtime = bool(re.search(r"<(?:script|link)\b[^>]+(?:src|href)=[\"']https?://", low))
    compatibility = 34
    compatibility += 14 if "local-first" in features else 0
    compatibility += 11 if "JSON state" in features else 0
    compatibility += 10 if "import/export" in features else 0
    compatibility += 8 if re.search(r"module|registry|interface|schema|api|adapter", low) else 0
    compatibility += 8 if not external_runtime else -6
    compatibility += 5 if "accessibility" in features else 0
    compatibility = max(10, min(96, compatibility))

    maturity = 15 + min(28, round(math.log2(max(size, 1) / 8_000 + 1) * 7))
    maturity += 8 if re.search(r"<form\b|<button\b|addEventListener|onclick", text, re.I) else 0
    maturity += 7 if "IndexedDB" in features or "JSON state" in features else 0
    maturity += 6 if "import/export" in features else 0
    maturity += 5 if "print-ready" in features else 0
    maturity += 5 if "tooltips/docs" in features else 0
    maturity += 5 if "accessibility" in features else 0
    maturity += 4 if "service worker" in features else 0
    maturity = min(94, maturity)
    return {"compatibility": compatibility, "evidence": evidence, "safety": safety, "maturity": maturity}


def classify_status(haystack: str, scores: dict[str, int]) -> str:
    low = haystack.lower()
    if re.search(r"speculative|science fiction|far future|quantum|galactic|cosmic|mythic|unverified mechanism", low):
        return "speculative concept"
    if re.search(r"hypothesis|research question|proposed mechanism|needs? validation|theoretical", low):
        return "hypothesis"
    if re.search(r"field[\s-]?test|pilot[\s-]?ready|deployment candidate|implementation guide|municipal pilot", low) and scores["safety"] >= 48:
        return "field-test candidate"
    if re.search(r"prototype|proof of concept|\bpoc\b|experimental|demo\b|simulator|game\b", low):
        return "experimental prototype"
    if re.search(r"agroforest|food forest|rainwater harvest|pollinator corridor|evidence ledger|local[\s-]?first|mutual aid|restoration guide", low) and not re.search(r"platform|system|architecture|engine|network", low):
        return "established idea"
    return "integration"


def questions_answered(text: str, features: list[str], layers: list[str], concepts: list[str]) -> list[str]:
    low = text.lower()
    questions = ["What problem space does this address?"]
    if re.search(r"implementation|how it works|workflow|steps?|method|deploy", low):
        questions.append("How might it be implemented?")
    if re.search(r"stakeholder|community|government|user|audience|institution|steward", low):
        questions.append("Who could use or govern it?")
    if PLACE_TERMS.search(text) or "deployment" in layers:
        questions.append("Where could it be adapted or deployed?")
    if "evidence language" in features or "research" in layers:
        questions.append("What evidence or sources are cited?")
    if "uncertainty handling" in features or "safety" in layers or "risk & safeguards" in concepts:
        questions.append("What risks, uncertainty, or safeguards are discussed?")
    if re.search(r"impact|outcome|metric|measure|indicator", low):
        questions.append("How might impact be measured?")
    if re.search(r"module|combine|interoper|interface|registry|schema", low):
        questions.append("What can this combine with?")
    return questions[:6]


class UnionFind:
    def __init__(self, count: int):
        self.parent = list(range(count))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def representative_score(build: dict) -> tuple[int, int, int, int]:
    rel = build["path"]
    return (
        explicit_version(rel),
        len(build["features"]),
        build["size"],
        -len(rel),
    )


def make_description(title: str, primary_layer: str, domains: list[str], concepts: list[str]) -> str:
    layer_phrase = {
        "concept": "A concept artifact exploring",
        "module": "A potentially reusable module for",
        "pattern": "A composable pattern connecting",
        "system": "A systems-level integration coordinating",
        "deployment": "A place-based deployment concept spanning",
        "dataset": "A structured data artifact supporting",
        "research": "A research-oriented artifact examining",
        "safety": "A safety-oriented artifact addressing",
        "innovation": "An innovation hypothesis exploring",
    }.get(primary_layer, "An archive artifact connecting")
    subjects = concepts[:2] or domains[:2]
    joined = " and ".join(subjects)
    return f"{layer_phrase} {joined}. Classification and readiness scores are archive-derived heuristics, not validation claims."


def useful_auxiliary(rel: str, ext: str) -> int:
    low = rel.lower()
    if "/.git/" in f"/{low}" or "/node_modules/" in f"/{low}":
        return -100
    score = 0
    if ext in {".csv", ".tsv", ".geojson"}:
        score += 18
    elif ext == ".json":
        score += 8
    elif ext == ".pdf":
        score += 12
    elif ext == ".md":
        score += 2
    for word, points in {
        "dataset": 12, "data": 5, "research": 12, "evidence": 10, "report": 8,
        "registry": 8, "catalog": 8, "manifest": 5, "ledger": 8, "paper": 10,
        "innovation": 8, "blueprint": 7, "method": 6, "audit": 8, "safety": 7,
        "governance": 5, "deployment": 4, "provenance": 8,
    }.items():
        if word in low:
            score += points
    if Path(rel).name.lower() in {"readme.md", "license", "license.md", "package.json", "package-lock.json"}:
        score -= 4
    return score


def find_card(cards: list[dict], *needles: str) -> dict | None:
    candidates = []
    for card in cards:
        hay = (card["path"] + " " + card["title"]).lower()
        score = sum(5 if needle.lower() in hay else 0 for needle in needles)
        if score:
            score += card["scores"]["maturity"] / 100
            candidates.append((score, card))
    return max(candidates, default=(0, None), key=lambda pair: pair[0])[1]


def build_recipes(cards: list[dict]) -> list[dict]:
    specs = [
        {
            "id": "conflict_evidence_loop",
            "title": "Conflict-safe evidence loop",
            "outcome": "Separate observation from interpretation, corroborate claims, and route high-risk signals into de-escalation instead of narrative escalation.",
            "terms": [("global/conflict/monitoring", "conflict monitoring"), ("ai_targeting_incident_ledger", "incident ledger"), ("conflict_deescalation",), ("reverse_manipulation", "agency garden")],
            "steps": ["Log observations and source independence", "Score uncertainty and alternative hypotheses", "Trigger human review thresholds", "Select reversible de-escalation actions"],
            "safetyGate": "No attribution or intervention without corroboration, proportionality, and human review.",
            "evidenceGate": "Preserve raw observations, source timestamps, dissenting interpretations, and confidence changes."
        },
        {
            "id": "ai_transition_safety_stack",
            "title": "AI transition safety stack",
            "outcome": "Connect disruption scenarios to concrete safeguards, successor careers, and monitored public outcomes.",
            "terms": [("antidisruption_regen_platform",), ("ai_displacement_safeguards",), ("regenerative_careers",), ("progen_engine",)],
            "steps": ["Model a disruption scenario", "Identify vulnerable groups and institutions", "Match safeguards and successor roles", "Monitor outcomes and revise"],
            "safetyGate": "Do not automate eligibility, punishment, or livelihood decisions; keep appeal and human override paths.",
            "evidenceGate": "Validate assumptions against labor data, lived experience, distributional impacts, and counterfactuals."
        },
        {
            "id": "biosphere_operations_pilot",
            "title": "Biosphere operations pilot",
            "outcome": "Turn ecological sensing, restoration choices, community governance, and impact tracking into one bounded pilot.",
            "terms": [("decision_atlas",), ("biosphere",), ("cascade_commons",), ("impacttracker", "impact tracker")],
            "steps": ["Define one watershed or habitat boundary", "Establish baseline data and uncertainty", "Co-design reversible interventions", "Publish outcomes and ecological side effects"],
            "safetyGate": "Require ecological review, local consent, stop conditions, and monitoring before any field intervention.",
            "evidenceGate": "Use baseline/control comparisons and report null or adverse outcomes alongside successes."
        },
        {
            "id": "edible_resilience_district",
            "title": "Edible resilience district",
            "outcome": "Combine public food infrastructure, canopy, water, and pollinator modules into a municipal-scale test.",
            "terms": [("public_resilience",), ("toronto_edible_upgrade",), ("global_pollinator",), ("water", "cascade")],
            "steps": ["Map public assets and community priorities", "Select climate-appropriate perennial species", "Integrate water and pollinator corridors", "Assign maintenance, access, and food-safety governance"],
            "safetyGate": "Screen species, allergens, contamination, accessibility, Indigenous rights, and long-term maintenance.",
            "evidenceGate": "Track canopy survival, food access, biodiversity, heat, runoff, maintenance cost, and community feedback."
        },
        {
            "id": "housing_to_dignity_pathway",
            "title": "Housing-to-dignity pathway",
            "outcome": "Connect immediate shelter, decentralized governance, food security, and livelihood pathways without coercive profiling.",
            "terms": [("canada_zero_homelessness",), ("decentralized_homelessness",), ("regenerative_careers",), ("child_hunger",)],
            "steps": ["Start with unconditional safety and housing", "Offer voluntary support pathways", "Link food and livelihood resources", "Let affected people govern success criteria"],
            "safetyGate": "No surveillance, forced treatment, punitive scoring, or loss of services for nonparticipation.",
            "evidenceGate": "Measure housing stability, wellbeing, service access, user-defined outcomes, and unintended exclusion."
        },
        {
            "id": "youth_agency_commons",
            "title": "Youth agency commons",
            "outcome": "Pair anti-manipulation safeguards with child-centered participation, local data, and auditable incident learning.",
            "terms": [("reverse_manipulation",), ("protecting_children_with_ai",), ("digital/democracy/portal",), ("ai_targeting_incident_ledger",)],
            "steps": ["Define rights and consent boundaries", "Map manipulative patterns without profiling children", "Provide local-first reporting and learning", "Escalate only through accountable human institutions"],
            "safetyGate": "Child rights, data minimization, guardian/advocate review, and non-retaliation are mandatory.",
            "evidenceGate": "Distinguish observed harms from inferred intent; include age-appropriate participatory evaluation."
        },
    ]
    recipes = []
    for spec in specs:
        components = []
        for terms in spec.pop("terms"):
            card = find_card(cards, *terms)
            if card and card["id"] not in components:
                components.append(card["id"])
        if len(components) >= 2:
            compatibility = round(sum(next(c for c in cards if c["id"] == cid)["scores"]["compatibility"] for cid in components) / len(components))
            recipes.append({**spec, "componentIds": components, "compatibility": compatibility})
    return recipes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.corpus.resolve()
    files = sorted(path for path in root.rglob("*") if path.is_file())

    all_groups: dict[str, list[dict]] = defaultdict(list)
    extension_counts: Counter[str] = Counter()
    top_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "bytes": 0})
    html_by_hash: dict[str, dict] = {}

    for index, path in enumerate(files, 1):
        rel = path.relative_to(root).as_posix()
        ext = path.suffix.lower() or "[no extension]"
        size = path.stat().st_size
        digest = sha256_file(path)
        extension_counts[ext] += 1
        top = rel.split("/", 1)[0]
        top_counts[top]["files"] += 1
        top_counts[top]["bytes"] += size
        all_groups[digest].append({"path": rel, "size": size, "ext": ext})

        if ext == ".html" and size > 0:
            text = safe_text(path)
            title = extract_title(text, path.stem if path.stem.lower() != "index" else path.parent.name)
            low = text.lower()
            features = detect_features(text)
            existing = html_by_hash.get(digest)
            record = {
                "path": rel,
                "size": size,
                "sha256": digest,
                "title": title,
                "text": text,
                "features": features,
            }
            if existing is None:
                record["paths"] = [rel]
                html_by_hash[digest] = record
            else:
                existing["paths"].append(rel)
                if representative_score(record) > representative_score(existing):
                    record["paths"] = existing["paths"]
                    html_by_hash[digest] = record

    builds = list(html_by_hash.values())
    uf = UnionFind(len(builds))
    seen_keys: dict[str, int] = {}
    for i, build in enumerate(builds):
        keys = set()
        tk = title_key(build["title"])
        if tk not in GENERIC_TITLES and len(tk) >= 8:
            keys.add("t:" + tk)
        for rel in build["paths"]:
            anchor = path_anchor(rel)
            if anchor not in GENERIC_TITLES and len(anchor) >= 5:
                keys.add("p:" + anchor)
        for key in keys:
            if key in seen_keys:
                uf.union(i, seen_keys[key])
            else:
                seen_keys[key] = i

    families: dict[int, list[dict]] = defaultdict(list)
    for i, build in enumerate(builds):
        families[uf.find(i)].append(build)

    cards: list[dict] = []
    for family_builds in families.values():
        representative = max(family_builds, key=representative_score)
        all_paths = sorted({p for build in family_builds for p in build["paths"]})
        family_text = representative["text"]
        signal = f"{representative['title']} {representative['path']} " + re.sub(r"<script\b.*?</script\s*>", " ", family_text[:180_000], flags=re.I | re.S)
        domains = classify_domains(signal)
        concepts = classify_concepts(signal, domains)
        primary_layer, layers = classify_layers(signal, representative["path"], ".html")
        scores = score_record(family_text, representative["size"], representative["features"])
        status = classify_status(signal, scores)
        card_id = "psc_" + hashlib.sha1((representative["sha256"] + "|" + min(all_paths)).encode()).hexdigest()[:11]
        versions = sorted(
            ({"path": b["path"], "sha256": b["sha256"], "size": b["size"], "version": explicit_version(b["path"])} for b in family_builds),
            key=lambda x: (x["version"], x["size"]), reverse=True,
        )
        cards.append({
            "id": card_id,
            "title": representative["title"],
            "description": make_description(representative["title"], primary_layer, domains, concepts),
            "path": representative["path"],
            "domain": domains[0],
            "domains": domains,
            "layer": primary_layer,
            "layers": layers,
            "status": status,
            "concepts": concepts,
            "features": representative["features"],
            "questions": questions_answered(family_text[:200_000], representative["features"], layers, concepts),
            "scores": scores,
            "provenance": {
                "sha256": representative["sha256"],
                "sizeBytes": representative["size"],
                "exactCopies": len(representative["paths"]),
                "familyFiles": len(all_paths),
                "distinctBuilds": len(family_builds),
                "aliases": all_paths[:18],
                "versions": versions[:10],
            },
        })

    cards.sort(key=lambda c: (-(c["scores"]["maturity"] + c["scores"]["evidence"] + c["scores"]["safety"]), c["title"].lower()))

    raw_inventory = []
    auxiliary_candidates = []
    for digest, group in all_groups.items():
        representative = min(group, key=lambda x: (len(x["path"]), x["path"]))
        raw_inventory.append({
            "path": representative["path"],
            "extension": representative["ext"],
            "sizeBytes": representative["size"],
            "sha256": digest[:16],
            "copies": len(group),
            "aliases": [x["path"] for x in sorted(group, key=lambda x: x["path"])[:8]],
        })
        score = useful_auxiliary(representative["path"], representative["ext"])
        if score > 2 and representative["ext"] in {".md", ".json", ".csv", ".tsv", ".geojson", ".pdf"}:
            auxiliary_candidates.append((score, digest, representative, group))

    raw_inventory.sort(key=lambda x: (x["extension"], x["path"].lower()))
    auxiliary_candidates.sort(key=lambda x: (-x[0], x[2]["path"].lower()))
    auxiliaries = []
    for score, digest, rep, group in auxiliary_candidates[:500]:
        path = root / Path(rep["path"])
        sample = ""
        if rep["ext"] in {".md", ".json", ".csv", ".tsv", ".geojson"} and rep["size"] <= 3_000_000:
            sample = safe_text(path, 120_000)
        title = humanize(path.name if path.stem.lower() != "readme" else path.parent.name)
        signal = f"{title} {rep['path']} {sample}"
        domains = classify_domains(signal)
        concepts = classify_concepts(signal, domains)
        layer, layers = classify_layers(signal, rep["path"], rep["ext"])
        if rep["ext"] in {".csv", ".tsv", ".json", ".geojson"} and "dataset" not in layers:
            layers.insert(0, "dataset")
            layer = "dataset"
        auxiliaries.append({
            "id": "aux_" + digest[:11],
            "title": title,
            "path": rep["path"],
            "extension": rep["ext"],
            "sizeBytes": rep["size"],
            "copies": len(group),
            "sha256": digest,
            "domain": domains[0],
            "layer": layer,
            "layers": layers,
            "concepts": concepts[:6],
            "description": make_description(title, layer, domains, concepts),
        })

    distinct_titles = {title_key(build["title"]) for build in builds if title_key(build["title"]) and title_key(build["title"]) not in GENERIC_TITLES}
    feature_counts = Counter()
    for build in builds:
        feature_counts.update(build["features"])
    status_counts = Counter(card["status"] for card in cards)
    domain_counts = Counter(card["domain"] for card in cards)
    layer_counts = Counter(card["layer"] for card in cards)

    extension_rows = [
        {"extension": ext, "count": count}
        for ext, count in sorted(extension_counts.items(), key=lambda pair: (-pair[1], pair[0]))
    ]
    top_dirs = [
        {"name": name, **values}
        for name, values in sorted(top_counts.items(), key=lambda pair: (-pair[1]["files"], -pair[1]["bytes"], pair[0]))[:32]
    ]
    data = {
        "schemaVersion": "1.0.0",
        "generated": "2026-08-31",
        "source": {
            "archiveName": "download.zip",
            "archiveSha256": ARCHIVE_SHA256,
            "compressedBytes": ARCHIVE_BYTES,
            "zipEntries": ZIP_ENTRIES,
            "method": "SHA-256 exact deduplication followed by conservative title/path version-family collapse; all classifications and scores are heuristic.",
        },
        "metrics": {
            "actualFiles": len(files),
            "uncompressedBytes": sum(path.stat().st_size for path in files),
            "exactDistinctFiles": len(all_groups),
            "duplicateFileInstances": len(files) - len(all_groups),
            "htmlFiles": extension_counts[".html"],
            "nonEmptyHtmlFiles": sum(1 for path in files if path.suffix.lower() == ".html" and path.stat().st_size > 0),
            "distinctHtmlBuilds": len(builds),
            "logicalHtmlFamilies": len(cards),
            "distinctNonGenericTitles": len(distinct_titles),
            "researchDatasetRecords": len(auxiliaries),
        },
        "extensionCounts": extension_rows,
        "featureCounts": [{"feature": name, "count": feature_counts[name], "percent": round(feature_counts[name] * 100 / max(1, len(builds)), 1)} for name in FEATURE_PATTERNS],
        "domainCounts": [{"name": k, "count": v} for k, v in domain_counts.most_common()],
        "layerCounts": [{"name": k, "count": v} for k, v in layer_counts.most_common()],
        "statusCounts": [{"name": k, "count": v} for k, v in status_counts.most_common()],
        "topDirectories": top_dirs,
        "definitions": {
            "statuses": {
                "established idea": "Uses practices with an existing real-world evidence base; this archive instance is still not independently validated.",
                "integration": "Combines known ideas or components in a distinctive architecture; integration value is plausible, not proven.",
                "hypothesis": "Makes a testable proposition that requires evidence, falsification criteria, and independent review.",
                "experimental prototype": "An interactive or technical demonstration suitable for controlled evaluation, not operational reliance.",
                "field-test candidate": "Structured enough for an ethics-reviewed, bounded, reversible pilot with monitoring and stop conditions.",
                "speculative concept": "Exploratory future-facing idea; mechanism, feasibility, or impact is substantially unverified.",
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
                "compatibility": "Interface-readiness estimate from local operation, structured data, import/export, modular language, accessibility, and external dependencies.",
                "evidence": "Documentation signal from sources, references, methodology, uncertainty, corroboration, and validation language—not a quality appraisal of cited evidence.",
                "safety": "Presence of safeguards, consent, privacy, uncertainty, reversibility, auditability, and zero-harm language—not a safety certification.",
                "maturity": "Artifact completeness signal from size, interaction, persistence, documentation, accessibility, and export/print support—not field readiness.",
            },
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
        "features": data["featureCounts"],
        "statuses": data["statusCounts"],
    }, indent=2))


if __name__ == "__main__":
    main()
