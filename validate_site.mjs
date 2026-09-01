import fs from 'fs';
import vm from 'vm';

const file = process.argv[2];
if (!file) throw new Error('Pass index.html path');
const html = fs.readFileSync(file, 'utf8');
const errors = [];
const warnings = [];
const requireCheck = (condition, message) => { if (!condition) errors.push(message); };

requireCheck(/^<!doctype html>/i.test(html), 'Missing HTML5 doctype');
requireCheck(/<noscript>[\s\S]*scientific caution/i.test(html), 'Missing useful noscript fallback');
requireCheck(/@media print/.test(html), 'Missing print stylesheet');
requireCheck(/indexedDB/.test(html), 'Missing IndexedDB persistence');
requireCheck(/psc-workspace-v1/.test(html), 'Missing workspace import/export schema');
requireCheck(/resetDialog/.test(html), 'Missing intentional reset confirmation');
requireCheck(/id="graphCanvas"/.test(html), 'Missing concept graph');
requireCheck(/Attributions & licenses/i.test(html), 'Missing attributions/licenses view');
requireCheck(/Zero-harm operating rule/i.test(html), 'Missing zero-harm framing');

const dataMatch = html.match(/<script id="commons-data" type="application\/json">([\s\S]*?)<\/script>/);
requireCheck(Boolean(dataMatch), 'Embedded catalogue JSON not found');
let data = null;
if (dataMatch) {
  try { data = JSON.parse(dataMatch[1]); } catch (error) { errors.push(`Catalogue JSON parse failed: ${error.message}`); }
}

const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const appScript = scripts.at(-1) || '';
try { new vm.Script(appScript, { filename: 'index-inline.js' }); } catch (error) { errors.push(`Inline JavaScript syntax failed: ${error.message}`); }

const forbidden = [
  [/<script\b[^>]*\bsrc\s*=/i, 'External script tag'],
  [/<link\b[^>]*\b(?:href|rel)\s*=\s*["']https?:/i, 'Remote stylesheet/resource'],
  [/<(?:img|iframe|video|audio|source)\b[^>]*\bsrc\s*=\s*["']https?:/i, 'Remote embedded media'],
  [/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/, 'Network API call'],
  [/C:\\Users\\|AppData\\Local|\/mnt\/data|work\\corpus/i, 'Local absolute path'],
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, 'Private-key block'],
  [/\bghp_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub-token-shaped string'],
  [/Canadian Military Awareness & Genocide Complicity Report/i, 'Quarantined allegation-bearing title'],
  [/Fact-Check: First Nations Audit Claims/i, 'Quarantined sensitive audit title'],
  [/regenerative_careers|progen_engine/i, 'Absent prior-conversation artifact leaked into catalogue'],
];
for (const [pattern, label] of forbidden) if (pattern.test(html)) errors.push(`${label} detected`);

if (data) {
  requireCheck(data.metrics.actualFiles === 4582, 'Raw file count must be 4,582');
  requireCheck(data.metrics.htmlFiles === 1372, 'HTML count must be 1,372');
  requireCheck(data.metrics.distinctHtmlBuilds === 1213, 'Distinct HTML count must be 1,213');
  requireCheck(data.metrics.versionFamilies === 922, 'Version family count must be 922');
  requireCheck(data.metrics.publicCatalogFamilies === data.cards.length, 'Public family metric does not equal card count');
  requireCheck(data.metrics.publicCatalogFamilies < data.metrics.versionFamilies, 'Quarantine did not reduce public family count');
  requireCheck(data.metrics.quarantinedFiles >= 1500, 'Expected quarantine aggregate is unexpectedly low');
  const ids = new Set(data.cards.map(c => c.id));
  requireCheck(ids.size === data.cards.length, 'Duplicate catalogue IDs');
  requireCheck(data.cards.every(c => Array.isArray(c.statuses) && c.statuses.includes(c.knowledgeStatus)), 'Invalid two-axis status metadata');
  requireCheck(data.cards.filter(c => c.buildStatus === 'field-test candidate').length === 1, 'Field-test candidate count must remain exactly one');
  requireCheck(data.cards.every(c => c.knowledgeStatus !== 'field-test candidate'), 'Build status leaked into knowledge axis');
  requireCheck(data.cards.every(c => ['compatibility','evidence','safety','maturity'].every(k => Number.isInteger(c.scores[k]) && c.scores[k] >= 0 && c.scores[k] <= 100)), 'Invalid score range');
  requireCheck(data.cards.every(c => Array.isArray(c.questions) && c.questions.every(q => typeof q.text === 'string' && typeof q.basis === 'string')), 'Invalid questions-answered metadata');
  requireCheck(data.recipes.every(r => r.componentIds.length >= 2 && r.componentIds.every(id => ids.has(id))), 'Recipe references missing catalogue components');
  requireCheck(data.rawInventory.every(r => ids.has(data.cards.find(c => c.path === r.path)?.id) || data.auxiliaries.some(a => a.path === r.path)), 'Raw file manifest leaked beyond allow-listed records');
  const educationCards = data.cards.filter(c => c.path.toLowerCase().startsWith('education2/'));
  requireCheck(educationCards.every(c => c.license === 'conflicting terms / legal review required'), 'education2 license conflict not preserved');
  requireCheck(!data.cards.some(c => /genocide|complicity report|audit claims|fact-check:/i.test(c.title)), 'Sensitive allegation-bearing card remains');
  requireCheck(!data.rawInventory.some(r => /aifinalwarning-chatgpt-history|ref\/dataset\/gpt\/trf|(?:^|\/)\.git\//i.test(r.path)), 'Sensitive path remains in public inventory');
}

const report = {
  file,
  bytes: Buffer.byteLength(html),
  sha256: (await import('crypto')).createHash('sha256').update(html).digest('hex'),
  cards: data?.cards?.length || 0,
  auxiliaries: data?.auxiliaries?.length || 0,
  recipes: data?.recipes?.length || 0,
  quarantinedFiles: data?.metrics?.quarantinedFiles || 0,
  externalDependencies: 0,
  errors,
  warnings,
};
console.log(JSON.stringify(report, null, 2));
if (errors.length) process.exit(1);
