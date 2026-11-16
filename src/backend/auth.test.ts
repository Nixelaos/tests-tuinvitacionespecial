import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL = 'redis://localhost:6379';
process.env.MASTER_API_KEY = 'super-secret-master-key-for-tests';
process.env.GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com';

const { normalizedEmailSchema } = await import(
  '../../../backend-tuinvitacionespecial/src/schemas/common.ts'
);
const {
  AuthError,
  clearGoogleJwksCache,
  extractBearerToken,
  verifyGoogleIdToken,
  verifyMasterApiKey,
} = await import('../../../backend-tuinvitacionespecial/src/lib/auth.ts');

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
const publicJwk = publicKey.export({ format: 'jwk' });

const { publicKey: rotatedPublicKey, privateKey: rotatedPrivateKey } =
  generateKeyPairSync('rsa', { modulusLength: 2048 });
const rotatedPublicJwk = rotatedPublicKey.export({ format: 'jwk' });

const signJwt = (
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signingKey = privateKey
): string => {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signer = createSign('RSA-SHA256');
  signer.update(`${encodedHeader}.${encodedPayload}`);
  signer.end();
  const signature = signer.sign(signingKey).toString('base64url');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
};

test('normalizedEmailSchema normaliza con trim + toLowerCase y valida formato', () => {
  const valid = normalizedEmailSchema.parse('  Planner.Wedding@Gmail.COM  ');
  assert.equal(valid, 'planner.wedding@gmail.com');

  assert.throws(() => normalizedEmailSchema.parse('correo-invalido'));
});

test('verifyMasterApiKey valida en tiempo constante y rechaza llaves inválidas', () => {
  assert.equal(verifyMasterApiKey('super-secret-master-key-for-tests'), true);
  assert.equal(verifyMasterApiKey('super-secret-master-key-for-testX'), false);
  assert.equal(verifyMasterApiKey('corta'), false);
  assert.equal(verifyMasterApiKey(''), false);
  assert.equal(verifyMasterApiKey(undefined), false);
});

test('extractBearerToken extrae tokens Bearer correctamente', () => {
  assert.equal(extractBearerToken('Bearer tok_123.456'), 'tok_123.456');
  assert.equal(extractBearerToken('bearer tok_123.456'), 'tok_123.456');
  assert.equal(extractBearerToken('Basic abc'), null);
  assert.equal(extractBearerToken(undefined), null);
});

test('verifyGoogleIdToken verifica firma RS256, normaliza email y rechaza claims inválidos', async (t) => {
  clearGoogleJwksCache();

  let fetchCalls = 0;
  let activeKeyId = 'key-1';

  t.mock.method(globalThis, 'fetch', async () => {
    fetchCalls += 1;
    const keys =
      activeKeyId === 'key-1'
        ? [{ ...publicJwk, kid: 'key-1', kty: 'RSA', alg: 'RS256', use: 'sig' }]
        : [{ ...rotatedPublicJwk, kid: 'key-2', kty: 'RSA', alg: 'RS256', use: 'sig' }];

    return new Response(JSON.stringify({ keys }), {
      status: 200,
      headers: {
        'content-type': 'application/json',
        'cache-control': 'public, max-age=300',
      },
    });
  });

  const futureExp = Math.floor(Date.now() / 1000) + 3600;

  // 1. Token válido (con email en mayúsculas para comprobar normalización)
  const validToken = signJwt(
    { alg: 'RS256', kid: 'key-1', typ: 'JWT' },
    {
      iss: 'https://accounts.google.com',
      aud: process.env.GOOGLE_CLIENT_ID,
      sub: 'google-sub-123',
      email: '  Novia.Ejemplo@Gmail.COM ',
      email_verified: true,
      name: 'Valentina',
      exp: futureExp,
    }
  );

  const user = await verifyGoogleIdToken(validToken);
  assert.deepEqual(user, {
    sub: 'google-sub-123',
    email: 'novia.ejemplo@gmail.com',
    name: 'Valentina',
  });
  assert.equal(fetchCalls, 1);

  // 2. Segunda verificación reutiliza caché JWKS
  await verifyGoogleIdToken(validToken);
  assert.equal(fetchCalls, 1);

  // 3. Token expirado
  const expiredToken = signJwt(
    { alg: 'RS256', kid: 'key-1' },
    {
      iss: 'https://accounts.google.com',
      aud: process.env.GOOGLE_CLIENT_ID,
      sub: 'google-sub-123',
      email: 'novia@gmail.com',
      email_verified: true,
      exp: Math.floor(Date.now() / 1000) - 10,
    }
  );
  await assert.rejects(() => verifyGoogleIdToken(expiredToken), AuthError);

  // 4. Audiencia incorrecta
  const wrongAudToken = signJwt(
    { alg: 'RS256', kid: 'key-1' },
    {
      iss: 'https://accounts.google.com',
      aud: 'otro-client-id',
      sub: 'google-sub-123',
      email: 'novia@gmail.com',
      email_verified: true,
      exp: futureExp,
    }
  );
  await assert.rejects(() => verifyGoogleIdToken(wrongAudToken), AuthError);

  // 5. Correo no verificado
  const unverifiedEmailToken = signJwt(
    { alg: 'RS256', kid: 'key-1' },
    {
      iss: 'https://accounts.google.com',
      aud: process.env.GOOGLE_CLIENT_ID,
      sub: 'google-sub-123',
      email: 'novia@gmail.com',
      email_verified: false,
      exp: futureExp,
    }
  );
  await assert.rejects(() => verifyGoogleIdToken(unverifiedEmailToken), AuthError);

  // 6. Firma alterada
  const tamperedParts = validToken.split('.');
  const tamperedToken = `${tamperedParts[0]}.${tamperedParts[1]}.invalid_sig`;
  await assert.rejects(() => verifyGoogleIdToken(tamperedToken), AuthError);

  // 7. Rotación de llaves (kid nuevo fuerza refresco de JWKS y valida correctamente)
  activeKeyId = 'key-2';
  const rotatedToken = signJwt(
    { alg: 'RS256', kid: 'key-2' },
    {
      iss: 'accounts.google.com',
      aud: process.env.GOOGLE_CLIENT_ID,
      sub: 'google-sub-456',
      email: 'planner@gmail.com',
      email_verified: true,
      exp: futureExp,
    },
    rotatedPrivateKey
  );
  const rotatedUser = await verifyGoogleIdToken(rotatedToken);
  assert.equal(rotatedUser.email, 'planner@gmail.com');
  assert.equal(fetchCalls, 2);
});
