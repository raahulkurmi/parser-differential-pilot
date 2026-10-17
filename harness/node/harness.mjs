// Node harness: node-json, node-jose, node-jsonwebtoken.
//
// Usage: node harness.mjs --parser <id> --corpus <dir> --pubkey <pem>   (JSONL on stdout)
// Canonical value encoding: docs/PREREGISTRATION.md section 5.2.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPublicKey } from 'node:crypto';
import * as jose from 'jose';
import jsonwebtoken from 'jsonwebtoken';

const FIELDS = ['iss', 'sub', 'aud', 'exp', 'iat'];
const ABSENT = { t: 'absent' };

function canon(v) {
  if (v === null) return { t: 'null' };
  if (typeof v === 'boolean') return { t: 'bool', v };
  if (typeof v === 'string') return { t: 'string', cp: [...v].map((c) => c.codePointAt(0)) };
  if (typeof v === 'number') {
    const dv = new DataView(new ArrayBuffer(8));
    dv.setFloat64(0, v);
    return { t: 'number', kind: 'f64', bits: dv.getBigUint64(0).toString(16).padStart(16, '0') };
  }
  if (Array.isArray(v)) return { t: 'array', v: v.map(canon) };
  if (typeof v === 'object') {
    const keys = Object.keys(v).sort();
    return { t: 'object', v: keys.map((k) => [canon(k), canon(v[k])]) };
  }
  return { t: 'other', v: `${typeof v}:${String(v)}` };
}

function fieldsFromMap(m) {
  const out = {};
  for (const f of FIELDS) out[f] = Object.prototype.hasOwnProperty.call(m, f) ? canon(m[f]) : ABSENT;
  return out;
}

function nodeJson(buf) {
  const obj = JSON.parse(buf.toString('utf8'));
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('top-level value is not an object');
  return fieldsFromMap(obj);
}

// jose: signature check with compactVerify, then jose's own claims-set decoder.
// decodeJwt uses the same strict TextDecoder + JSON.parse step as jwtVerify,
// but without jwtVerify's mandatory exp/nbf time checks.
async function nodeJose(token, key) {
  await jose.compactVerify(token, key, { algorithms: ['RS256'] });
  return fieldsFromMap(jose.decodeJwt(token));
}

function nodeJsonwebtoken(token, pem) {
  const claims = jsonwebtoken.verify(token, pem, { algorithms: ['RS256'], ignoreExpiration: true, ignoreNotBefore: true });
  if (claims === null || typeof claims !== 'object') throw new Error('payload is not an object');
  return fieldsFromMap(claims);
}

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : dflt;
}

const parser = arg('parser');
const corpus = arg('corpus', 'corpus');
const pem = readFileSync(arg('pubkey', 'testdata/keys/TEST_ONLY_rs256_public.pem'), 'utf8');
if (!['node-json', 'node-jose', 'node-jsonwebtoken'].includes(parser)) {
  console.error('unknown parser', parser);
  process.exit(2);
}
const key = createPublicKey(pem);
const ids = readFileSync(join(corpus, 'MANIFEST.csv'), 'utf8')
  .split('\n')
  .slice(1)
  .filter((l) => l.length > 0)
  .map((l) => l.split(',')[0]);

for (const id of ids) {
  const rec = { schema: 1, case: id, parser };
  try {
    let fields;
    if (parser === 'node-json') {
      fields = nodeJson(readFileSync(join(corpus, `${id}.json`)));
    } else {
      const token = readFileSync(join(corpus, 'tokens', `${id}.jwt`), 'ascii').trim();
      fields = parser === 'node-jose' ? await nodeJose(token, key) : nodeJsonwebtoken(token, pem);
    }
    Object.assign(rec, { outcome: 'ACCEPT', error: null, fields });
  } catch (e) {
    if (e && e.code === 'ENOENT') throw e;
    Object.assign(rec, { outcome: 'REJECT', error: `${e?.name}: ${e?.message}`, fields: null });
  }
  process.stdout.write(JSON.stringify(rec) + '\n');
}
