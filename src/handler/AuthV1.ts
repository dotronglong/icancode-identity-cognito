import { Request, Response, Router } from 'express';
import { handle, log, reply } from '@icancode/express';
import {
  BadRequestError,
  InternalServerError,
  RequestValidationError,
  ResourceNotFoundError,
  UnauthorizedError,
  createDebug,
} from '@icancode/base';
import {
  AdminInitiateAuthCommand,
  CodeMismatchException,
  ConfirmSignUpCommand,
  InvalidPasswordException,
  NotAuthorizedException,
  SignUpCommand,
  UsernameExistsException,
  UserNotConfirmedException,
  UserNotFoundException,
} from '@aws-sdk/client-cognito-identity-provider';
import Joi from 'joi';
import cognito from '../lib/cognito';
import { now } from '../lib/time';
import { getBearerToken } from '../lib/header';
import { UserNotConfirmedError } from '../lib/error';
import { signRSA } from '../lib/jwt';
import { decodeJwt } from 'jose';
import axios, { AxiosError } from 'axios';

const debug = createDebug('icancode:identity-cognito');

export function getAuthV1Router(): Router {
  const router = Router();
  router.post('/signup', handle(createUser));
  router.post('/confirm', handle(confirmUser));
  router.post('/signin', handle(authenticateUser));
  router.get('/token', handle(createToken));

  return router;
}

async function createUser(request: Request, response: Response) {
  interface UserPayload {
    username: string;
    email: string;
    password: string;
  }
  const schema = Joi.object({
    username: Joi.string().min(3).max(24).required(),
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });

  const { error, value } = schema.validate(request.body);
  if (error) {
    throw RequestValidationError(error.message);
  }

  const body: UserPayload = value as UserPayload;
  const secretHash = cognito.getSecretHash(body.username);
  const command = new SignUpCommand({
    ClientId: cognito.clientId,
    SecretHash: secretHash,
    Username: body.username,
    Password: body.password,
    UserAttributes: [{ Name: 'email', Value: body.email }],
  });

  try {
    log(response).mask(['Request.Body.password']);
    const result = await cognito.client.send(command);
    const data = {
      email: body.email,
      username: body.username,
      userId: result.UserSub,
      userConfirmed: result.UserConfirmed,
    };

    reply(response).status(201).json(data);
  } catch (e) {
    debug(e);
    if (
      e instanceof InvalidPasswordException ||
      e instanceof UsernameExistsException
    ) {
      throw RequestValidationError(e.message);
    } else {
      throw BadRequestError;
    }
  }
}

async function confirmUser(request: Request, response: Response) {
  interface ConfirmUserPayload {
    username: string;
    confirmationCode: string;
  }

  const schema = Joi.object({
    username: Joi.string().required(),
    confirmationCode: Joi.string().required(),
  });

  const { error, value } = schema.validate(request.body);
  if (error) {
    throw RequestValidationError(error.message);
  }

  const body = value as ConfirmUserPayload;
  const secretHash = cognito.getSecretHash(body.username);
  const command = new ConfirmSignUpCommand({
    ClientId: cognito.clientId,
    SecretHash: secretHash,
    Username: body.username,
    ConfirmationCode: body.confirmationCode,
  });

  try {
    await cognito.client.send(command);
    reply(response).status(200).json({
      username: body.username,
      userConfirmed: true,
    });
  } catch (e) {
    if (e instanceof CodeMismatchException) {
      throw RequestValidationError(e.message);
    } else if (e instanceof NotAuthorizedException) {
      throw UnauthorizedError;
    } else {
      throw BadRequestError;
    }
  }
}

async function authenticateUser(request: Request, response: Response) {
  interface AuthenticationPayload {
    username: string;
    password: string;
  }
  const schema = Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
  });

  const { error, value } = schema.validate(request.body);
  if (error) {
    throw RequestValidationError(error.message);
  }

  const body = value as AuthenticationPayload;
  const secretHash = cognito.getSecretHash(body.username);
  const command = new AdminInitiateAuthCommand({
    ClientId: cognito.clientId,
    UserPoolId: cognito.userPoolId,
    AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
    AuthParameters: {
      USERNAME: body.username,
      PASSWORD: body.password,
      SECRET_HASH: secretHash,
    },
  });

  try {
    log(response).mask([
      'Request.Body.password',
      'Response.Body.accessToken',
      'Response.Body.refreshToken',
    ]);
    const result = await cognito.client.send(command);
    let data = {};
    if (
      result.AuthenticationResult &&
      result.AuthenticationResult.AccessToken
    ) {
      const decodedPayload = decodeJwt(result.AuthenticationResult.AccessToken);
      const expiresIn = parseInt(process.env.JWT_EXPIRES_IN || '3600');
      const accessToken = await signRSA(
        {
          username: body.username,
          sub: decodedPayload.sub,
        },
        {
          expiresIn,
        }
      );
      data = {
        accessToken: accessToken,
        refreshToken: result.AuthenticationResult.RefreshToken,
        expiry: now() + expiresIn,
      };
    }
    reply(response).status(200).json(data);
  } catch (e) {
    if (e instanceof UserNotFoundException) {
      throw ResourceNotFoundError;
    } else if (e instanceof UserNotConfirmedException) {
      throw UserNotConfirmedError;
    } else if (e instanceof NotAuthorizedException) {
      throw UnauthorizedError;
    } else {
      throw BadRequestError;
    }
  }
}

async function refreshToken(request: Request, response: Response) {
  const username = request.get('username');
  if (!username) {
    throw BadRequestError;
  }
  const secretHash = cognito.getSecretHash(username);

  const token = getBearerToken(request, response);
  const command = new AdminInitiateAuthCommand({
    UserPoolId: cognito.userPoolId,
    ClientId: cognito.clientId,
    AuthFlow: 'REFRESH_TOKEN_AUTH',
    AuthParameters: {
      REFRESH_TOKEN: token,
      SECRET_HASH: secretHash,
    },
  });

  try {
    const result = await cognito.client.send(command);
    log(response).mask(['Response.Body.accessToken']);
    let data = {};
    if (
      result.AuthenticationResult &&
      result.AuthenticationResult.AccessToken
    ) {
      const decodedPayload = decodeJwt(result.AuthenticationResult.AccessToken);
      const expiresIn = parseInt(process.env.JWT_EXPIRES_IN || '3600');
      const accessToken = await signRSA(
        {
          username,
          sub: decodedPayload.sub,
        },
        {
          expiresIn,
        }
      );
      data = {
        accessToken: accessToken,
        expiry: now() + expiresIn,
      };
    }
    reply(response).status(200).json(data);
  } catch (e) {
    if (e instanceof UserNotFoundException) {
      throw ResourceNotFoundError;
    } else if (
      e instanceof UserNotConfirmedException ||
      e instanceof NotAuthorizedException
    ) {
      throw UnauthorizedError;
    } else {
      throw BadRequestError;
    }
  }
}

async function exchangeToken(
  code: string,
  request: Request,
  response: Response
) {
  const clientId = process.env.COGNITO_CLIENT_ID;
  const clientSecret = process.env.COGNITO_CLIENT_SECRET;
  const domain = process.env.COGNITO_DOMAIN;
  const redirectUri = process.env.COGNITO_REDIRECT_URI;
  if (!clientId || !clientSecret || !domain || !redirectUri) {
    log(response).error('Missing environment variables.');
    throw InternalServerError;
  }

  const tokenUrl = `https://${domain}/oauth2/token`;
  const params = new URLSearchParams();
  params.append('grant_type', 'authorization_code');
  params.append('client_id', clientId);
  params.append('client_secret', clientSecret);
  params.append('code', code);
  params.append('redirect_uri', redirectUri);

  try {
    log(response).mask([
      'Request.Headers.authorization-code',
      'Response.Body.accessToken',
      'Response.Body.refreshToken',
    ]);
    const result = await axios.post(tokenUrl, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const { id_token, refresh_token } = result.data;
    const decodedPayload = decodeJwt(id_token);
    if (!decodedPayload['cognito:username']) {
      log(response).error('Unable to detect cognito:username');
      throw InternalServerError;
    }

    let data = {};
    const username = `${decodedPayload['cognito:username'] || ''}`;
    const expiresIn = parseInt(process.env.JWT_EXPIRES_IN || '3600');
    const accessToken = await signRSA(
      {
        username,
        sub: decodedPayload.sub,
      },
      {
        expiresIn,
      }
    );
    data = {
      accessToken: accessToken,
      refreshToken: refresh_token,
      expiry: now() + expiresIn,
    };

    reply(response)
      .status(200)
      .set(
        'Access-Control-Expose-Headers',
        'Content-Length, Content-Type, Username'
      )
      .set('Username', username)
      .json(data);
  } catch (error) {
    debug(error);
    if (error instanceof AxiosError) {
      if (error.status === 400) {
        throw BadRequestError;
      }
      log(response).error(
        `Error exchanging authorization code: ${error.message}`
      );
    }
    throw InternalServerError;
  }
}

async function createToken(request: Request, response: Response) {
  const code = request.query['code'];
  if (code) {
    return exchangeToken(`${code}`, request, response);
  }

  return refreshToken(request, response);
}
