/**
 * Revisor independiente — piezas compartidas por los dos niveles.
 *
 * El NIVEL 1 (análisis) produce un artefacto; el NIVEL 2 (publicación) lo consume.
 * Entre los dos hay una frontera de confianza: el artefacto viaja por el almacén
 * de artefactos de Actions y, para el nivel 2, es DATO NO CONFIABLE. Por eso la
 * validación del esquema vive acá y es estricta: todo lo que no esté previsto se
 * rechaza, nunca se ignora.
 */
import { createHash } from 'node:crypto';

export const ESQUEMA = 'ReviewerAnalysisV1';
export const LIMITE_ARTEFACTO_BYTES = 256 * 1024;
export const SEVERIDADES = Object.freeze(['CRITICAL', 'MAJOR', 'MINOR', 'OBSERVATION']);
export const SEVERIDADES_BLOQUEANTES = Object.freeze(['CRITICAL', 'MAJOR']);
export const LIMITE_HALLAZGOS = 200;
export const LIMITE_CRITERIOS = 64;

const RE_REPO = /^[A-Za-z0-9._-]{1,100}\/[A-Za-z0-9._-]{1,100}$/;
const RE_SHA40 = /^[0-9a-f]{40}$/;
const RE_SHA64 = /^[0-9a-f]{64}$/;
/* Permitimos salto de línea y tabulación; cualquier otro control es rechazo
   explícito, nunca saneo silencioso. */
const RE_CONTROL = new RegExp('[\\u0000-\\u0008\\u000b-\\u001f\\u007f]');

export function sha256(texto) {
  return createHash('sha256').update(texto, 'utf8').digest('hex');
}

/**
 * Manifiesto canónico del diff. Los DOS niveles lo calculan con esta misma
 * función y sobre la misma forma de respuesta de GitHub, de modo que el nivel 2
 * pueda recomputarlo y comprobar que revisó exactamente lo que el PR contiene.
 * Ordenado por ruta: el orden de la API no es contractual.
 */
export function manifiestoCanonico(archivos) {
  const lineas = [...archivos]
    .map((a) => ({
      filename: String(a.filename),
      status: String(a.status),
      sha: String(a.sha ?? ''),
      additions: Number(a.additions ?? 0),
      deletions: Number(a.deletions ?? 0),
    }))
    .sort((x, y) => (x.filename < y.filename ? -1 : x.filename > y.filename ? 1 : 0))
    .map((a) => [a.filename, a.status, a.sha, `+${a.additions}`, `-${a.deletions}`].join('\t'));
  return `${lineas.join('\n')}\n`;
}

function textoValido(v, maximo) {
  return typeof v === 'string' && v.length <= maximo && !RE_CONTROL.test(v);
}

function clavesExactas(obj, permitidas) {
  const propias = Object.keys(obj);
  if (propias.length !== permitidas.length) return false;
  return permitidas.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

function esObjetoLlano(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Valida el artefacto del nivel 1 tratándolo como hostil.
 * Devuelve { ok: true, valor } o { ok: false, razon }.
 */
export function validarArtefacto(textoCrudo) {
  if (typeof textoCrudo !== 'string') return { ok: false, razon: 'ARTIFACT_NOT_TEXT' };
  if (Buffer.byteLength(textoCrudo, 'utf8') > LIMITE_ARTEFACTO_BYTES) {
    return { ok: false, razon: 'ARTIFACT_TOO_LARGE' };
  }
  /* Antes de parsear: estas claves nunca son legítimas en este esquema. */
  if (textoCrudo.includes('__proto__') || textoCrudo.includes('constructor')) {
    return { ok: false, razon: 'ARTIFACT_FORBIDDEN_KEY' };
  }
  let v;
  try {
    v = JSON.parse(textoCrudo);
  } catch {
    return { ok: false, razon: 'ARTIFACT_MALFORMED_JSON' };
  }
  if (!esObjetoLlano(v)) return { ok: false, razon: 'ARTIFACT_NOT_OBJECT' };

  const raiz = ['schema', 'repository', 'prNumber', 'reviewedSha', 'diffSha256',
    'reviewerIdentity', 'generatedAt', 'analysis', 'findings'];
  if (!clavesExactas(v, raiz)) return { ok: false, razon: 'ARTIFACT_UNEXPECTED_KEYS' };

  if (v.schema !== ESQUEMA) return { ok: false, razon: 'ARTIFACT_SCHEMA_MISMATCH' };
  if (!textoValido(v.repository, 201) || !RE_REPO.test(v.repository)) {
    return { ok: false, razon: 'ARTIFACT_REPOSITORY_INVALID' };
  }
  if (!Number.isSafeInteger(v.prNumber) || v.prNumber < 1 || v.prNumber > 10000000) {
    return { ok: false, razon: 'ARTIFACT_PR_INVALID' };
  }
  if (!textoValido(v.reviewedSha, 40) || !RE_SHA40.test(v.reviewedSha)) {
    return { ok: false, razon: 'ARTIFACT_SHA_INVALID' };
  }
  if (!textoValido(v.diffSha256, 64) || !RE_SHA64.test(v.diffSha256)) {
    return { ok: false, razon: 'ARTIFACT_DIFF_DIGEST_INVALID' };
  }
  if (!textoValido(v.reviewerIdentity, 120) || v.reviewerIdentity.length === 0) {
    return { ok: false, razon: 'ARTIFACT_REVIEWER_INVALID' };
  }
  if (!textoValido(v.generatedAt, 40)) return { ok: false, razon: 'ARTIFACT_DATE_INVALID' };

  if (!esObjetoLlano(v.analysis)) return { ok: false, razon: 'ARTIFACT_ANALYSIS_INVALID' };
  if (!clavesExactas(v.analysis, ['engine', 'engineAvailable', 'substantive', 'criteria'])) {
    return { ok: false, razon: 'ARTIFACT_ANALYSIS_UNEXPECTED_KEYS' };
  }
  const an = v.analysis;
  if (!textoValido(an.engine, 120) || an.engine.length === 0) {
    return { ok: false, razon: 'ARTIFACT_ENGINE_INVALID' };
  }
  if (typeof an.engineAvailable !== 'boolean' || typeof an.substantive !== 'boolean') {
    return { ok: false, razon: 'ARTIFACT_ANALYSIS_FLAGS_INVALID' };
  }
  if (!Array.isArray(an.criteria) || an.criteria.length === 0 || an.criteria.length > LIMITE_CRITERIOS) {
    return { ok: false, razon: 'ARTIFACT_CRITERIA_INVALID' };
  }
  for (const c of an.criteria) {
    if (!esObjetoLlano(c) || !clavesExactas(c, ['id', 'title', 'blocking', 'evaluated', 'detail'])) {
      return { ok: false, razon: 'ARTIFACT_CRITERION_SHAPE' };
    }
    if (!textoValido(c.id, 60) || c.id.length === 0) return { ok: false, razon: 'ARTIFACT_CRITERION_ID' };
    if (!textoValido(c.title, 200) || !textoValido(c.detail, 500)) {
      return { ok: false, razon: 'ARTIFACT_CRITERION_TEXT' };
    }
    if (typeof c.blocking !== 'boolean' || typeof c.evaluated !== 'boolean') {
      return { ok: false, razon: 'ARTIFACT_CRITERION_FLAGS' };
    }
  }

  if (!Array.isArray(v.findings) || v.findings.length > LIMITE_HALLAZGOS) {
    return { ok: false, razon: 'ARTIFACT_FINDINGS_INVALID' };
  }
  for (const h of v.findings) {
    if (!esObjetoLlano(h) || !clavesExactas(h, ['severity', 'criterion', 'path', 'summary'])) {
      return { ok: false, razon: 'ARTIFACT_FINDING_SHAPE' };
    }
    if (!SEVERIDADES.includes(h.severity)) return { ok: false, razon: 'ARTIFACT_FINDING_SEVERITY' };
    if (!textoValido(h.criterion, 60) || !textoValido(h.path, 400) || !textoValido(h.summary, 500)) {
      return { ok: false, razon: 'ARTIFACT_FINDING_TEXT' };
    }
  }
  return { ok: true, valor: v };
}

/**
 * Decide el veredicto a partir del análisis.
 *
 * Reglas, en este orden:
 *  1. Sin análisis sustantivo -> NO se publica nada. Jamás una aprobación fija.
 *  2. Un criterio bloqueante que no pudo evaluarse NO equivale a PASS.
 *  3. CRITICAL o MAJOR -> REQUEST_CHANGES.
 *  4. Sólo MINOR/OBSERVATION -> APPROVE con los hallazgos en el cuerpo, para que
 *     no generen ciclos de revisión interminables.
 */
export function decidir(artefacto) {
  const an = artefacto.analysis;
  if (!an.engineAvailable || !an.substantive) {
    return {
      publicar: false, evento: null, resultado: 'NO_SUBSTANTIVE_ANALYSIS',
      motivos: ['ANALYSIS_NOT_SUBSTANTIVE'],
    };
  }
  const sinEvaluar = an.criteria.filter((c) => c.blocking && !c.evaluated).map((c) => c.id);
  if (sinEvaluar.length > 0) {
    return {
      publicar: true, evento: 'REQUEST_CHANGES', resultado: 'REWORK',
      motivos: sinEvaluar.map((id) => `CONTROL_NOT_EVALUATED:${id}`),
    };
  }
  const bloqueantes = artefacto.findings.filter((h) => SEVERIDADES_BLOQUEANTES.includes(h.severity));
  if (bloqueantes.length > 0) {
    return {
      publicar: true, evento: 'REQUEST_CHANGES', resultado: 'REWORK',
      motivos: bloqueantes.map((h) => `${h.severity}:${h.criterion}`),
    };
  }
  return { publicar: true, evento: 'APPROVE', resultado: 'GO', motivos: [] };
}

/** Cuerpo de la revisión: determinista, con la evidencia estructurada completa. */
export function cuerpoDeRevision(artefacto, veredicto) {
  const l = [];
  l.push('## Revisión independiente — Agent V2');
  l.push('');
  l.push(`- Revisor: \`${artefacto.reviewerIdentity}\``);
  l.push(`- Repositorio: \`${artefacto.repository}\` · PR \`#${artefacto.prNumber}\``);
  l.push(`- SHA revisado: \`${artefacto.reviewedSha}\``);
  l.push(`- SHA-256 del diff: \`${artefacto.diffSha256}\``);
  l.push(`- Motor: \`${artefacto.analysis.engine}\``);
  l.push(`- Generado: \`${artefacto.generatedAt}\``);
  l.push(`- Resultado: **${veredicto.resultado}**`);
  l.push('');
  l.push('### Criterios aplicados');
  for (const c of artefacto.analysis.criteria) {
    const marca = c.evaluated ? 'evaluado' : 'NO EVALUADO';
    const cola = c.detail ? ` — ${c.detail}` : '';
    l.push(`- \`${c.id}\` ${c.title} — ${marca}${c.blocking ? ' · bloqueante' : ''}${cola}`);
  }
  l.push('');
  l.push('### Hallazgos');
  if (artefacto.findings.length === 0) l.push('- Ninguno.');
  for (const h of artefacto.findings) {
    l.push(`- **${h.severity}** \`${h.criterion}\` \`${h.path}\` — ${h.summary}`);
  }
  if (veredicto.motivos.length > 0) {
    l.push('');
    l.push('### Motivos del veredicto');
    for (const m of veredicto.motivos) l.push(`- \`${m}\``);
  }
  l.push('');
  l.push('_Esta revisión se refiere al SHA indicado. Un commit posterior la invalida._');
  return l.join('\n');
}
