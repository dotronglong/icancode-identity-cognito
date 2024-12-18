import {
  JWTVerifyOptions,
  KeyLike,
  SignJWT,
  importPKCS8,
  importSPKI,
  jwtVerify,
} from 'jose';
import fs from 'fs';
import { HashMap } from '@icancode/base';
import { RSAPrivateKeyNotFound, RSAPublicKeyNotFound } from './error';
import { now } from './time';

let rsaPrivateKey: KeyLike;
let rsaPublicKey: KeyLike;

async function loadPrivateKeyRSA() {
  if (rsaPrivateKey) {
    return rsaPrivateKey;
  }

  if (!process.env.JWT_RSA_KEY) {
    throw RSAPrivateKeyNotFound;
  }

  const rsaPrivateKeyPem = fs.readFileSync(process.env.JWT_RSA_KEY, 'utf8');
  rsaPrivateKey = await importPKCS8(rsaPrivateKeyPem, 'RS256');

  return rsaPrivateKey;
}

async function loadPublicKeyRSA() {
  if (rsaPublicKey) {
    return rsaPublicKey;
  }

  if (!process.env.JWT_RSA_PUBLIC) {
    throw RSAPublicKeyNotFound;
  }

  const rsaPublicKeyPem = fs.readFileSync(process.env.JWT_RSA_PUBLIC, 'utf8');
  rsaPublicKey = await importSPKI(rsaPublicKeyPem, 'RS256');

  return rsaPublicKey;
}

interface TokenOptions {
  expiresIn?: number;
  issuer?: string;
  subject?: string;
}

export async function signRSA(
  payload: HashMap,
  options?: TokenOptions
): Promise<string> {
  const privateKey = await loadPrivateKeyRSA();
  const signer = new SignJWT(payload).setProtectedHeader({
    alg: 'RS256',
    typ: 'JWT',
  });

  if (options) {
    if (options.expiresIn) {
      signer.setExpirationTime(now() + options.expiresIn);
    }
    if (options.issuer) {
      signer.setIssuer(options.issuer);
    }
    if (options.subject) {
      signer.setSubject(options.subject);
    }
  }

  const token = await signer.sign(privateKey);

  return token;
}

export async function verifyRSA(
  token: string,
  options?: JWTVerifyOptions
): Promise<HashMap> {
  const publicKey = await loadPublicKeyRSA();
  const { payload } = await jwtVerify(token, publicKey, options);
  return payload;
}
