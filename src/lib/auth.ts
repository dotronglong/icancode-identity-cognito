import User from '../entity/User';
import { HashMap } from '@icancode/base';
import { Response } from 'express';

export function getUser(response: Response): User | undefined {
  return response.locals.authenticatedUser;
}

export function setUser(response: Response, payload: HashMap) {
  response.locals.authenticatedUser = new User(payload);
}
