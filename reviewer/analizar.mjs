/**
 * NIVEL 1 — análisis. Corre con el disparador `pull_request`.
 *
 * Propiedades de seguridad de este nivel:
 *  - NUNCA referencia la clave privada del GitHub App. Es la garantía estructural
 *    de que ningún código llegado en un PR puede ejecutarse con acceso a ella.
 *  - NUNCA hace checkout del HEAD del PR ni ejecuta nada traído por el PR: no
 *    corre `npm ci`, ni scripts del paquete, ni los tests. Lee el diff por la API.
 *    El workflow hace checkout de la rama por defecto, que es código de confianza.
 *  - El diff y los textos del PR son DATOS. Se comparan contra patrones; nunca
 *    se evalúan, ni se interpolan en un shell, ni se usan como rutas.
 *
 * Sin dependencias externas: sólo módulos internos de Node, para que este
 * directorio se pueda instalar tal cual en el repositorio del producto.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { manifiestoCanonico, sha256, ESQUEMA } from './comun.mjs';

export const MOTOR = 'deterministic-policy-v1';
export const MAX_PAGINAS = 10;
export const POR_PAGINA = 100;
export const LIMITE_ARCHIVOS = 20;
export const LIMITE_LINEAS = 600;

/* Patrones de material sensible. Se buscan SÓLO en líneas agregadas del diff. */
export const PATRONES_SECRETO = Object.freeze([
  ['github_token', /\b(gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}/],
  ['clave_privada', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['openai_key', /\bsk-[A-Za-z0-9_-]{20,}/],
  ['anthropic_key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['aws_key', /\bAKIA[0-9A-Z]{16}\b/],
  ['cadena_de_conexion', /\b(?:postgres|postgresql|mysql|mongodb)(?:\+srv)?:\/\/[^\s:@/]+:[^\s@/]+@/],
  ['asignacion_sensible', /\b(?:password|passwd|secret|api_?key|private_?key|access_?token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i],
]);

/* Debilitamiento de controles. También sólo en líneas agregadas. */
export const PATRONES_DEBILITAMIENTO = Object.freeze([
  ['continue_on_error', /^\s*continue-on-error\s*:\s*true/],
  ['git_no_verify', /--no-verify\b/],
  ['exit_enmascarado', /\|\|\s*true\s*$/],
  ['test_saltado', /\b(?:it|test|describe)\s*\.\s*skip\s*\(/],
  ['test_exclusivo', /\b(?:it|test|describe)\s*\.\s*only\s*\(/],
  ['test_desactivado', /\bx(?:it|describe)\s*\(/],
  ['permisos_irrestrictos', /bypassPermissions/],
  ['typecheck_relajado', /@ts-(?:ignore|nocheck)\b/],
]);

const EXT_BINARIA = /\.(png|jpe?g|gif|webp|avif|ico|pdf|zip|gz|tgz|woff2?|ttf|eot|mp[34]|mov|wasm)$/i;

function bajo(ruta, prefijos) {
  return prefijos.some((p) => ruta === p || ruta.startsWith(p));
}

function lineasAgregadas(patch) {
  return patch
    .split('\n')
    .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
    .map((l) => l.slice(1));
}

/** Cliente HTTP mínimo contra la API de GitHub. Sólo lecturas. */
export function clienteGitHub(token, buscar = fetch) {
  return async function pedir(ruta) {
    const r = await buscar(`https://api.github.com${ruta}`, {
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'audiofilo-independent-reviewer',
      },
    });
    if (!r.ok) return { ok: false, estado: r.status };
    return { ok: true, cuerpo: await r.json() };
  };
}

/**
 * Trae TODAS las páginas de archivos del PR, o declara la lista incompleta.
 * Una lista parcial no se usa como si fuera completa: los criterios de alcance
 * quedan sin evaluar y eso bloquea más adelante.
 */
export async function traerArchivos(pedir, repo, pr) {
  const acumulado = [];
  for (let pagina = 1; pagina <= MAX_PAGINAS; pagina += 1) {
    const r = await pedir(`/repos/${repo}/pulls/${pr}/files?per_page=${POR_PAGINA}&page=${pagina}`);
    if (!r.ok) return { ok: false, razon: `FILES_FETCH_FAILED_${r.estado}` };
    if (!Array.isArray(r.cuerpo)) return { ok: false, razon: 'FILES_SHAPE_UNEXPECTED' };
    acumulado.push(...r.cuerpo);
    if (r.cuerpo.length < POR_PAGINA) return { ok: true, archivos: acumulado };
  }
  return { ok: false, razon: 'FILES_PAGINATION_INCOMPLETE' };
}

/**
 * Aplica los criterios. Devuelve { criterios, hallazgos }.
 *
 * `evaluated: false` significa literalmente "este control no se pudo ejecutar".
 * No es un PASS: `decidir()` lo convierte en REQUEST_CHANGES si es bloqueante.
 */
export function analizar({ archivos, listaCompleta, politica, politicaDigest }) {
  const criterios = [];
  const hallazgos = [];
  const permitidas = politica.allowedPaths ?? [];
  const protegidas = politica.protectedPaths ?? [];

  criterios.push({
    id: 'policy-identity', title: 'Política de referencia anclada por digest',
    blocking: false, evaluated: true, detail: `sha256=${politicaDigest}`,
  });

  /* 1 y 2 — alcance. Dependen de la lista COMPLETA de archivos. */
  for (const [id, title, prueba, severidad, texto] of [
    ['scope-allowed-paths', 'Todo archivo modificado cae dentro de las rutas permitidas',
      (r) => permitidas.length > 0 && !bajo(r, permitidas), 'CRITICAL',
      (r) => `fuera de allowedPaths (${permitidas.join(', ')}): ${r}`],
    ['scope-protected-paths', 'Ningún archivo modificado toca una ruta protegida',
      (r) => bajo(r, protegidas), 'CRITICAL',
      (r) => `ruta protegida modificada: ${r}`],
  ]) {
    const violaciones = listaCompleta ? archivos.map((a) => a.filename).filter(prueba) : [];
    criterios.push({
      id, title, blocking: true, evaluated: listaCompleta,
      detail: listaCompleta ? `${violaciones.length} violación(es)` : 'lista de archivos incompleta',
    });
    for (const r of violaciones) hallazgos.push({ severity: severidad, criterion: id, path: r, summary: texto(r) });
  }

  /* 3 y 4 — contenido. Dependen de que GitHub haya devuelto el `patch` de cada
     archivo de texto. Si falta alguno, el control NO se evaluó. */
  const sinParche = archivos
    .filter((a) => typeof a.patch !== 'string' && a.status !== 'removed' && !EXT_BINARIA.test(a.filename))
    .map((a) => a.filename);
  const contenidoEvaluable = listaCompleta && sinParche.length === 0;
  const conParche = archivos.filter((a) => typeof a.patch === 'string');

  for (const [id, title, patrones, severidad, etiqueta] of [
    ['secret-material', 'El diff no introduce material sensible', PATRONES_SECRETO, 'CRITICAL', 'posible secreto'],
    ['gate-weakening', 'El diff no debilita controles ni pruebas', PATRONES_DEBILITAMIENTO, 'MAJOR', 'control debilitado'],
  ]) {
    criterios.push({
      id, title, blocking: true, evaluated: contenidoEvaluable,
      detail: contenidoEvaluable
        ? `${conParche.length} archivo(s) con diff legible`
        : `sin diff legible: ${sinParche.slice(0, 5).join(', ') || 'lista incompleta'}`,
    });
    if (!contenidoEvaluable) continue;
    for (const a of conParche) {
      for (const linea of lineasAgregadas(a.patch)) {
        for (const [nombre, re] of patrones) {
          if (re.test(linea)) {
            hallazgos.push({
              severity: severidad, criterion: id, path: a.filename,
              summary: `${etiqueta} (${nombre}) en una línea agregada`,
            });
          }
        }
      }
    }
  }

  /* 5 — señal de pruebas. Un cambio de producto sin ningún test tocado. */
  const rutas = archivos.map((a) => a.filename);
  const hayProducto = rutas.some((r) => bajo(r, permitidas) && !/(?:^|\/)__tests__\/|\.test\.|\.spec\./.test(r));
  const hayPrueba = rutas.some((r) => /(?:^|\/)(?:__tests__|tests)\/|\.test\.|\.spec\./.test(r));
  criterios.push({
    id: 'test-coverage-signal', title: 'Un cambio de producto viene acompañado de pruebas',
    blocking: true, evaluated: listaCompleta,
    detail: listaCompleta ? `producto=${hayProducto} pruebas=${hayPrueba}` : 'lista de archivos incompleta',
  });
  if (listaCompleta && hayProducto && !hayPrueba) {
    hallazgos.push({
      severity: 'MAJOR', criterion: 'test-coverage-signal', path: '(conjunto del PR)',
      summary: 'el PR modifica código de producto y no toca ninguna prueba',
    });
  }

  /* 6 — tamaño. No bloqueante: informa, no genera ciclos. */
  const lineas = archivos.reduce((t, a) => t + Number(a.additions ?? 0) + Number(a.deletions ?? 0), 0);
  const grande = archivos.length > LIMITE_ARCHIVOS || lineas > LIMITE_LINEAS;
  criterios.push({
    id: 'change-size', title: 'El cambio es revisable de una sola vez',
    blocking: false, evaluated: listaCompleta,
    detail: `${archivos.length} archivo(s), ${lineas} línea(s)`,
  });
  if (listaCompleta && grande) {
    hallazgos.push({
      severity: 'MINOR', criterion: 'change-size', path: '(conjunto del PR)',
      summary: `${archivos.length} archivos y ${lineas} líneas superan el umbral de revisión atómica`,
    });
  }

  return { criterios, hallazgos };
}

/** Construye el artefacto del nivel 1. No escribe nada por sí misma. */
export async function construir({ pedir, repo, pr, politica, politicaDigest, revisor, ahora }) {
  const p = await pedir(`/repos/${repo}/pulls/${pr}`);
  if (!p.ok) return { ok: false, razon: `PULL_FETCH_FAILED_${p.estado}` };
  const pull = p.cuerpo;
  const headSha = pull?.head?.sha;
  if (typeof headSha !== 'string' || !/^[0-9a-f]{40}$/.test(headSha)) {
    return { ok: false, razon: 'PULL_HEAD_SHA_UNEXPECTED' };
  }

  const f = await traerArchivos(pedir, repo, pr);
  const archivos = f.ok ? f.archivos : [];
  const { criterios, hallazgos } = analizar({
    archivos, listaCompleta: f.ok, politica, politicaDigest,
  });

  /* El motor determinista SÍ está disponible; lo que no hay es análisis
     semántico. `substantive` afirma únicamente que se evaluaron criterios
     reales sobre el contenido del diff, no que la revisión sea exhaustiva. */
  const artefacto = {
    schema: ESQUEMA,
    repository: repo,
    prNumber: Number(pr),
    reviewedSha: headSha,
    diffSha256: sha256(manifiestoCanonico(archivos)),
    reviewerIdentity: revisor,
    generatedAt: ahora,
    analysis: {
      engine: MOTOR,
      engineAvailable: true,
      substantive: criterios.some((c) => c.blocking && c.evaluated),
      criteria: criterios,
    },
    findings: hallazgos,
  };
  return { ok: true, artefacto, listaCompleta: f.ok, razonLista: f.ok ? null : f.razon };
}

async function principal() {
  const env = process.env;
  const faltan = ['GITHUB_REPOSITORY', 'PR_NUMBER', 'GITHUB_TOKEN', 'REVIEWER_IDENTITY', 'OUT']
    .filter((k) => !env[k]);
  if (faltan.length > 0) {
    console.error(`ANALISIS=STOP RAZON=ENV_MISSING:${faltan.join(',')}`);
    process.exit(2);
  }
  const rutaPolitica = env.POLICY_PATH ?? 'reviewer/policy.json';
  let politica;
  let politicaDigest;
  try {
    const crudo = readFileSync(rutaPolitica, 'utf8');
    politicaDigest = sha256(crudo);
    politica = JSON.parse(crudo);
  } catch {
    console.error(`ANALISIS=STOP RAZON=POLICY_UNREADABLE:${rutaPolitica}`);
    process.exit(2);
  }

  const r = await construir({
    pedir: clienteGitHub(env.GITHUB_TOKEN),
    repo: env.GITHUB_REPOSITORY,
    pr: Number(env.PR_NUMBER),
    politica,
    politicaDigest,
    revisor: env.REVIEWER_IDENTITY,
    ahora: new Date().toISOString(),
  });
  if (!r.ok) {
    console.error(`ANALISIS=STOP RAZON=${r.razon}`);
    process.exit(2);
  }
  writeFileSync(env.OUT, `${JSON.stringify(r.artefacto, null, 2)}\n`, 'utf8');
  console.log(`ANALISIS=OK SHA=${r.artefacto.reviewedSha} DIFF_SHA256=${r.artefacto.diffSha256}`);
  console.log(`ANALISIS_CRITERIOS=${r.artefacto.analysis.criteria.length} HALLAZGOS=${r.artefacto.findings.length}`);
  if (!r.listaCompleta) console.log(`ANALISIS_LISTA_INCOMPLETA=${r.razonLista}`);
}

if (process.argv[1] && process.argv[1].endsWith('analizar.mjs')) {
  principal().catch((e) => {
    console.error(`ANALISIS=STOP RAZON=UNEXPECTED:${e?.message ?? 'sin mensaje'}`);
    process.exit(2);
  });
}
