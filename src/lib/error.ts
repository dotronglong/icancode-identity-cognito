import { HttpError } from '@icancode/base';

export const UserNotConfirmedError: HttpError = {
  status: 401,
  code: 'request.unauthorized',
  message: 'User is not confirmed',
};

export const RSAPrivateKeyNotFound: HttpError = {
  status: 500,
  code: 'server.key_missing',
  message: 'Unable to sign RSA signature',
};

export const RSAPublicKeyNotFound: HttpError = {
  status: 500,
  code: 'server.key_missing',
  message: 'Unable to verify RSA signature',
};
