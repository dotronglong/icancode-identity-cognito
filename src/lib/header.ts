import { UnauthorizedError } from '@icancode/base';
import { log } from '@icancode/express';
import { Request, Response } from 'express';

export function getBearerToken(request: Request, response: Response): string {
  const authHeader = request.get('authorization');

  if (!authHeader) {
    log(response).info('Authorization header is missing');
    throw UnauthorizedError;
  }

  if (!authHeader.startsWith('Bearer ')) {
    log(response).info('Invalid Authorization header format');
    throw UnauthorizedError;
  }

  return authHeader.split(' ')[1];
}
