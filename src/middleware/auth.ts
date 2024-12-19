import { Request, Response } from 'express';
import { UnauthorizedError } from '@icancode/base';
import { log } from '@icancode/express';
import { setUser } from '../lib/auth';
import { getBearerToken } from '../lib/header';
import { verifyRSA } from '../lib/jwt';
import { env } from '../lib/env';
import cognito from '../lib/cognito';

export default async function auth(request: Request, response: Response) {
  const token = getBearerToken(request, response);
  try {
    if (env.COGNITO_USE_JWT) {
      const payload = await verifyRSA(token);
      setUser(response, {
        username: payload.username,
        userId: payload.sub,
      });
    } else {
      const payload = await cognito.verifyAccessToken(token);
      setUser(response, {
        username: payload.username,
        userId: payload.sub,
      });
    }
  } catch (e: any) {
    log(response).error(`Failed to verify token: ${e.message || 'unknown'}`);
    throw UnauthorizedError;
  }
}
