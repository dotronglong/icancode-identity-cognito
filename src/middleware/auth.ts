import { Request, Response } from 'express';
import { UnauthorizedError } from '@icancode/base';
import { log } from '@icancode/express';
import { setUser } from '@lib/auth';
import { getBearerToken } from '@lib/header';
import { verifyRSA } from '@lib/jwt';

export default async function auth(request: Request, response: Response) {
  const token = getBearerToken(request, response);
  try {
    const payload = await verifyRSA(token);
    setUser(response, {
      username: payload.username,
      userId: payload.sub,
    });
  } catch (e: any) {
    log(response).error(`Failed to verify token: ${e.message || 'unknown'}`);
    throw UnauthorizedError;
  }
}
