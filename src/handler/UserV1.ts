import { Request, Response, Router } from 'express';
import { handle, reply } from '@icancode/express';
import {
  BadRequestError,
  ForbiddenError,
  RequestValidationError,
  UnauthorizedError,
} from '@icancode/base';
import {
  AdminGetUserCommand,
  AdminUpdateUserAttributesCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import auth from '../middleware/auth';
import { getUser } from '../lib/auth';
import cognito from '../lib/cognito';
import Joi from 'joi';

export function getUserV1Router(): Router {
  const router = Router();
  router.get('/:username/profile', handle(auth), handle(getUserProfile));
  router.patch('/:username/profile', handle(auth), handle(updateUserProfile));

  return router;
}

async function getUserProfile(request: Request, response: Response) {
  const username = request.params['username'];
  const authenticatedUser = getUser(response);

  if (authenticatedUser === undefined) {
    throw UnauthorizedError;
  } else if (authenticatedUser.username !== username) {
    throw ForbiddenError;
  }

  const command = new AdminGetUserCommand({
    UserPoolId: cognito.userPoolId,
    Username: username,
  });
  const result = await cognito.client.send(command);
  const attributes = result.UserAttributes || [];
  const user = {
    username: result.Username,
    email: attributes.find((attr) => attr.Name === 'email')?.Value,
    userId: attributes.find((attr) => attr.Name === 'sub')?.Value,
    region: attributes.find((attr) => attr.Name === 'custom:region')?.Value,
    enabled: result.Enabled,
    lastModifiedDate: result.UserLastModifiedDate,
  };

  reply(response).status(200).json(user);
}

async function updateUserProfile(request: Request, response: Response) {
  const username = request.params['username'];
  const authenticatedUser = getUser(response);

  if (authenticatedUser === undefined) {
    throw UnauthorizedError;
  } else if (authenticatedUser.username !== username) {
    throw ForbiddenError;
  }

  interface UpdateUserProfilePayload {
    region?: string;
  }
  const schema = Joi.object({
    region: Joi.string().allow('us', 'sg').only(),
  });

  const { error, value } = schema.validate(request.body);
  if (error) {
    throw RequestValidationError(error.message);
  }

  const body = value as UpdateUserProfilePayload;
  if (Object.keys(body).length === 0) {
    throw BadRequestError;
  }

  const command = new AdminUpdateUserAttributesCommand({
    UserPoolId: cognito.userPoolId,
    Username: username,
    UserAttributes: [{ Name: 'custom:region', Value: body.region }],
  });

  await cognito.client.send(command);
  reply(response).status(200).json({});
}
