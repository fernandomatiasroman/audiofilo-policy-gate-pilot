/**
 * NIVEL 2 — publicación privilegiada. Corre con el disparador `workflow_run`.
 *
 * Propiedades de seguridad de este nivel:
 *  - NUNCA hace checkout del HEAD del PR. En `workflow_run`, `actions/checkout`
 *    sin `ref` trae la rama por defecto, y la DEFINICIÓN del workflow también
 *    sale de la rama por defecto: un PR no puede modificar ni el código ni el
 *    workflow que manejan la clave.
 *  - No se usa `pull_request_target`. El código que corre acá es de confianza y
 *    el contenido del PR nunca se ejecuta.
 *  - El artefacto del nivel 1 es DATO NO CONFIABLE: se valida con el esquema
 *    estricto y, además, cada afirmación suya se vuelve a comprobar contra la
 *    API de GitHub (repositorio, PR, SHA, autor, digest del diff).
 *  - Todas las paradas que no necesitan la credencial se evalúan ANTES de
 *    tocarla. El contenido de la clave nunca se imprime: toda salida pasa por
 *    `redactar()`.
 *  - El `GITHUB_TOKEN` del job sólo necesita `actions: read` para bajar el
 *    artefacto. La revisión se publica con el token de instalación del App.
 */
import { readFileSync } from 'node:fs';
import { createSign } from 'node:crypto';
import { validarArtefacto, decidir, cuerpoDeRevision, manifiestoCanonico, sha256 } from './comun.mjs';

export const MAX_PAGINAS = 10;
export const POR_PAGINA = 100;

/** Sustituye cualquier aparición del material sensible por un marcador. */
export function redactar(texto, secretos) {
  let s = String(texto);
  for (const sec of secretos) {
    if (typeof sec === 'string' && sec.length >= 8) s = s.split(sec).join('[REDACTADO]');
  }
  return s;
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** JWT RS256 para autenticar como el App. La clave nunca sale de esta función. */
export function firmarJwt(appId, pem, segundos) {
  const cabecera = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const carga = b64u(JSON.stringify({ iat: segundos - 60, exp: segundos + 480, iss: String(appId) }));
  const firma = createSign('RSA-SHA256').update(`${cabecera}.${carga}`).end().sign(pem);
  return `${cabecera}.${carga}.${b64u(firma)}`;
}

function cabeceras(credencial) {
  return {
    authorization: `Bearer ${credencial}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'audiofilo-independent-reviewer',
  };
}

async function traerArchivos(http, credencial, repo, pr) {
  const acumulado = [];
  for (let pagina = 1; pagina <= MAX_PAGINAS; pagina += 1) {
    const r = await http(
      `https://api.github.com/repos/${repo}/pulls/${pr}/files?per_page=${POR_PAGINA}&page=${pagina}`,
      { method: 'GET', headers: cabeceras(credencial) },
    );
    if (!r.ok || !Array.isArray(r.cuerpo)) return { ok: false };
    acumulado.push(...r.cuerpo);
    if (r.cuerpo.length < POR_PAGINA) return { ok: true, archivos: acumulado };
  }
  return { ok: false };
}

/**
 * Ejecuta la publicación. `http` y `ahora` se inyectan para poder probar sin
 * red ni credenciales reales.
 *
 * Devuelve { estado, razon?, evento?, resultado?, revisionId? }.
 */
export async function publicar({ env, artefactoCrudo, http, ahora, emitir = () => {} }) {
  const clave = env.AUDIOFILO_REVIEWER_APP_PRIVATE_KEY ?? '';
  const secretos = [clave];
  const log = (m) => emitir(redactar(m, secretos));
  const parar = (razon) => {
    log(`PUBLICACION=STOP RAZON=${razon}`);
    return { estado: 'STOP', razon };
  };

  /* ── Comprobaciones que NO necesitan la credencial ───────────────────────── */

  const v = validarArtefacto(artefactoCrudo);
  if (!v.ok) return parar(`ARTIFACT_INVALID:${v.razon}`);
  const art = v.valor;

  const repo = env.GITHUB_REPOSITORY ?? '';
  if (art.repository !== repo) return parar('REPO_IDENTITY_MISMATCH');
  if ((env.RUN_HEAD_REPOSITORY ?? repo) !== repo) return parar('REPO_IDENTITY_MISMATCH');
  if (env.RUN_EVENT !== 'pull_request') return parar('EVENT_NOT_PULL_REQUEST');
  if (env.RUN_HEAD_SHA !== art.reviewedSha) return parar('SHA_MISMATCH');

  const veredicto = decidir(art);
  if (!veredicto.publicar) return parar(`NO_SUBSTANTIVE_ANALYSIS:${veredicto.motivos.join(',')}`);

  const appId = Number(env.AUDIOFILO_REVIEWER_APP_ID);
  if (!Number.isSafeInteger(appId) || appId <= 0) return parar('APP_ID_INVALID');
  if (clave.length === 0) return parar('SECRET_ABSENT');

  /* ── Autenticación como el App ───────────────────────────────────────────── */

  let jwt;
  try {
    jwt = firmarJwt(appId, clave, Math.floor(ahora / 1000));
  } catch {
    return parar('AUTH_FAILED:JWT_SIGN');
  }

  const appR = await http('https://api.github.com/app', { method: 'GET', headers: cabeceras(jwt) });
  if (!appR.ok) return parar(`AUTH_FAILED:APP_${appR.estado}`);
  if (typeof appR.cuerpo?.slug !== 'string' || !Number.isSafeInteger(appR.cuerpo?.id)) {
    return parar('UNEXPECTED_RESPONSE:APP');
  }
  if (appR.cuerpo.id !== appId) return parar('AUTH_FAILED:APP_ID_DIVERGENT');
  const identidadReal = `${appR.cuerpo.slug}[bot]`;
  if (identidadReal !== art.reviewerIdentity) return parar('REVIEWER_IDENTITY_MISMATCH');
  log(`PUBLICACION_IDENTIDAD=${identidadReal} APP_ID=${appId}`);

  const instR = await http(`https://api.github.com/repos/${repo}/installation`, {
    method: 'GET', headers: cabeceras(jwt),
  });
  if (!instR.ok) return parar(`AUTH_FAILED:INSTALLATION_${instR.estado}`);
  const instId = instR.cuerpo?.id;
  if (!Number.isSafeInteger(instId)) return parar('UNEXPECTED_RESPONSE:INSTALLATION');

  const tokR = await http(`https://api.github.com/app/installations/${instId}/access_tokens`, {
    method: 'POST',
    headers: { ...cabeceras(jwt), 'content-type': 'application/json' },
    cuerpoEnviado: JSON.stringify({ repositories: [repo.split('/')[1]] }),
  });
  if (!tokR.ok) return parar(`AUTH_FAILED:TOKEN_${tokR.estado}`);
  const token = tokR.cuerpo?.token;
  if (typeof token !== 'string' || token.length === 0) return parar('UNEXPECTED_RESPONSE:TOKEN');
  secretos.push(token);
  log('PUBLICACION_AUTENTICACION=OK');

  /* ── Re-verificación contra GitHub con la identidad del revisor ───────────── */

  const prR = await http(`https://api.github.com/repos/${repo}/pulls/${art.prNumber}`, {
    method: 'GET', headers: cabeceras(token),
  });
  if (prR.estado === 404) return parar('PR_NOT_FOUND');
  if (!prR.ok) return parar(`UNEXPECTED_RESPONSE:PULL_${prR.estado}`);
  const pull = prR.cuerpo;
  if (typeof pull?.head?.sha !== 'string' || typeof pull?.user?.login !== 'string') {
    return parar('UNEXPECTED_RESPONSE:PULL_SHAPE');
  }
  /* Si el PR avanzó después del análisis, la revisión previa queda obsoleta. */
  if (pull.head.sha !== art.reviewedSha) return parar('REVIEW_STALE');
  if (pull.base?.repo?.full_name !== undefined && pull.base.repo.full_name !== repo) {
    return parar('REPO_IDENTITY_MISMATCH');
  }
  /* El revisor no puede ser quien implementó. */
  if (pull.user.login === art.reviewerIdentity || pull.user.login === identidadReal) {
    return parar('REVIEW_BY_IMPLEMENTER');
  }

  const f = await traerArchivos(http, token, repo, art.prNumber);
  if (!f.ok) return parar('UNEXPECTED_RESPONSE:FILES');
  const digestAhora = sha256(manifiestoCanonico(f.archivos));
  /* Segunda defensa contra la obsolescencia: el contenido del PR cambió aunque
     el SHA de cabeza coincida (reescritura de historia, por ejemplo). */
  if (digestAhora !== art.diffSha256) return parar('DIFF_MISMATCH');

  const cuerpo = cuerpoDeRevision(art, veredicto);
  /* `DRY_RUN` es de TRES estados y falla cerrado: '1' ensaya, '0' publica, y
     cualquier otra cosa —incluida la variable sin definir, que en Actions llega
     como cadena vacía— detiene la operación. Publicar con una identidad
     privilegiada no puede depender de la AUSENCIA de una variable. */
  const modo = env.DRY_RUN ?? '';
  if (modo === '1') {
    log(`PUBLICACION=DRY_RUN EVENTO=${veredicto.evento} RESULTADO=${veredicto.resultado}`);
    return { estado: 'DRY_RUN', evento: veredicto.evento, resultado: veredicto.resultado, cuerpo };
  }
  if (modo !== '0') return parar('DRY_RUN_UNSET');

  const revR = await http(`https://api.github.com/repos/${repo}/pulls/${art.prNumber}/reviews`, {
    method: 'POST',
    headers: { ...cabeceras(token), 'content-type': 'application/json' },
    cuerpoEnviado: JSON.stringify({ commit_id: art.reviewedSha, body: cuerpo, event: veredicto.evento }),
  });
  if (!revR.ok) return parar(`PUBLISH_FAILED:${revR.estado}`);
  const revisionId = revR.cuerpo?.id;
  if (!Number.isSafeInteger(revisionId)) return parar('UNEXPECTED_RESPONSE:REVIEW');
  log(`PUBLICACION=OK EVENTO=${veredicto.evento} RESULTADO=${veredicto.resultado} REVIEW_ID=${revisionId}`);
  return { estado: 'OK', evento: veredicto.evento, resultado: veredicto.resultado, revisionId };
}

/** Adaptador de `fetch` a la forma que espera `publicar()`. */
export function clienteReal() {
  return async function http(url, opciones) {
    const r = await fetch(url, {
      method: opciones.method,
      headers: opciones.headers,
      body: opciones.cuerpoEnviado,
    });
    let cuerpo = null;
    try {
      cuerpo = await r.json();
    } catch {
      cuerpo = null;
    }
    return { ok: r.ok, estado: r.status, cuerpo };
  };
}

async function principal() {
  const env = process.env;
  if (!env.ARTIFACT) {
    console.error('PUBLICACION=STOP RAZON=ENV_MISSING:ARTIFACT');
    process.exit(2);
  }
  let crudo;
  try {
    crudo = readFileSync(env.ARTIFACT, 'utf8');
  } catch {
    console.error('PUBLICACION=STOP RAZON=ARTIFACT_UNREADABLE');
    process.exit(2);
  }
  const r = await publicar({
    env, artefactoCrudo: crudo, http: clienteReal(), ahora: Date.now(),
    emitir: (m) => console.log(m),
  });
  if (r.estado === 'STOP') process.exit(3);
}

if (process.argv[1] && process.argv[1].endsWith('publicar.mjs')) {
  principal().catch((e) => {
    /* El mensaje de una excepción podría arrastrar la clave: se redacta. */
    const seguro = redactar(e?.message ?? 'sin mensaje', [process.env.AUDIOFILO_REVIEWER_APP_PRIVATE_KEY ?? '']);
    console.error(`PUBLICACION=STOP RAZON=UNEXPECTED:${seguro}`);
    process.exit(2);
  });
}
