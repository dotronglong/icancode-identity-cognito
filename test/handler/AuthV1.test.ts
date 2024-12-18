import 'dotenv/config';
import request from 'supertest';
import express from 'express';
import { now } from '../../src/lib/time';
import { UserNotConfirmedError } from '../../src/lib/error';
import {
  RequestValidationError,
  ResourceNotFoundError,
  UnauthorizedError,
} from '@icancode/base';
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  AdminInitiateAuthCommand,
  ConfirmSignUpCommand,
  UserNotFoundException,
  UserNotConfirmedException,
  NotAuthorizedException,
  InvalidPasswordException,
  CodeMismatchException,
} from '@aws-sdk/client-cognito-identity-provider';
import { createApp } from '../bootstrap';

jest.mock('@aws-sdk/client-cognito-identity-provider', () => {
  const mockSend = jest.fn();

  return {
    CognitoIdentityProviderClient: jest.fn(() => ({
      send: mockSend,
    })),
    SignUpCommand: jest.fn(),
    AdminInitiateAuthCommand: jest.fn(),
    ConfirmSignUpCommand: jest.fn(),
    __setMockSend: (fn: jest.Mock) => {
      mockSend.mockImplementation(fn);
    },
    UserNotFoundException: jest.requireActual(
      '@aws-sdk/client-cognito-identity-provider'
    ).UserNotFoundException,
    UserNotConfirmedException: jest.requireActual(
      '@aws-sdk/client-cognito-identity-provider'
    ).UserNotConfirmedException,
    NotAuthorizedException: jest.requireActual(
      '@aws-sdk/client-cognito-identity-provider'
    ).NotAuthorizedException,
    InvalidPasswordException: jest.requireActual(
      '@aws-sdk/client-cognito-identity-provider'
    ).InvalidPasswordException,
    CodeMismatchException: jest.requireActual(
      '@aws-sdk/client-cognito-identity-provider'
    ).CodeMismatchException,
  };
});

jest.mock('jose', () => {
  return {
    decodeJwt: jest.fn().mockReturnValue({ sub: 'test-user-id' }),
  };
});

jest.mock('../../src/lib/jwt', () => {
  return {
    signRSA: jest.fn().mockResolvedValue('test-access-token'),
  };
});

describe('AuthV1', () => {
  let app: express.Express;
  let client: CognitoIdentityProviderClient;

  beforeAll(async () => {
    app = await createApp();
  });

  beforeEach(() => {
    client = new CognitoIdentityProviderClient({ region: 'us-east-1' });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /v1/auth/signup', () => {
    it('should return 400 if fields are missing', async () => {
      const response = await request(app)
        .post('/v1/auth/signup')
        .send({ password: 'my123' });

      expect(response.status).toBe(400);
    });

    it('should return 201 if request is OK', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof SignUpCommand) {
          return Promise.resolve({
            UserSub: 'test-user-id',
            UserConfirmed: false,
          });
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const response = await request(app).post('/v1/auth/signup').send({
        email: 'test@domain.com',
        username: 'test',
        password: 'my123',
      });

      expect(response.status).toBe(201);
      expect(response.body.email).toBe('test@domain.com');
      expect(response.body.username).toBe('test');
      expect(response.body.userId).toBe('test-user-id');
      expect(response.body.userConfirmed).toBe(false);
    });

    it('should return RequestValidationError if password does not meet requirements', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof SignUpCommand) {
          return Promise.reject(
            new InvalidPasswordException({
              message: 'Invalid password',
              $metadata: {},
            })
          );
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const error = RequestValidationError('Invalid password');

      const response = await request(app).post('/v1/auth/signup').send({
        email: 'test@domain.com',
        username: 'test',
        password: 'my123',
      });

      expect(response.status).toBe(error.status);
      expect(response.body.code).toBe(error.code);
      expect(response.body.message).toBe(error.message);
    });
  });

  describe('POST /v1/auth/signin', () => {
    it('should return 400 if fields are missing', async () => {
      const response = await request(app)
        .post('/v1/auth/signin')
        .send({ password: 'my123' });

      expect(response.status).toBe(400);
    });

    it('should return 200 if request is OK', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof AdminInitiateAuthCommand) {
          return Promise.resolve({
            AuthenticationResult: {
              AccessToken: 'test-access-token',
              RefreshToken: 'test-refresh-token',
              ExpiresIn: 3600,
            },
          });
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const current = now();
      const response = await request(app)
        .post('/v1/auth/signin')
        .send({ username: 'test', password: 'my123' });

      expect(response.status).toBe(200);
      expect(response.body.accessToken).toBe('test-access-token');
      expect(response.body.refreshToken).toBe('test-refresh-token');
      expect(response.body.expiry).toBe(current + 3600);
    });

    it('should return ResourceNotFoundError if encounters UserNotFoundException', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof AdminInitiateAuthCommand) {
          return Promise.reject(
            new UserNotFoundException({
              message: '',
              $metadata: {},
            })
          );
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const response = await request(app)
        .post('/v1/auth/signin')
        .send({ username: 'test', password: 'my123' });

      expect(response.status).toBe(ResourceNotFoundError.status);
      expect(response.body.code).toBe(ResourceNotFoundError.code);
    });

    it('should return UnauthorizedError if encounters UserNotConfirmedException', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof AdminInitiateAuthCommand) {
          return Promise.reject(
            new UserNotConfirmedException({
              message: '',
              $metadata: {},
            })
          );
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const response = await request(app)
        .post('/v1/auth/signin')
        .send({ username: 'test', password: 'my123' });

      expect(response.status).toBe(UnauthorizedError.status);
      expect(response.body.code).toBe(UnauthorizedError.code);
    });

    it('should return UnauthorizedError if encounters NotAuthorizedException', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof AdminInitiateAuthCommand) {
          return Promise.reject(
            new NotAuthorizedException({
              message: '',
              $metadata: {},
            })
          );
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const response = await request(app)
        .post('/v1/auth/signin')
        .send({ username: 'test', password: 'my123' });

      expect(response.status).toBe(UnauthorizedError.status);
      expect(response.body.code).toBe(UnauthorizedError.code);
    });

    it('should return UserNotConfirmedError if encounters UserNotConfirmedException', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof AdminInitiateAuthCommand) {
          return Promise.reject(
            new UserNotConfirmedException({
              message: '',
              $metadata: {},
            })
          );
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const response = await request(app)
        .post('/v1/auth/signin')
        .send({ username: 'test', password: 'my123' });

      expect(response.status).toBe(UserNotConfirmedError.status);
      expect(response.body.code).toBe(UserNotConfirmedError.code);
      expect(response.body.message).toBe(UserNotConfirmedError.message);
    });
  });

  describe('POST /v1/auth/confirm', () => {
    it('should return 400 if fields are missing', async () => {
      const response = await request(app)
        .post('/v1/auth/confirm')
        .send({ username: 'test' });

      expect(response.status).toBe(400);
    });

    it('should return 200 if request is OK', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof ConfirmSignUpCommand) {
          return Promise.resolve({});
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const response = await request(app)
        .post('/v1/auth/confirm')
        .send({ username: 'test', confirmationCode: '123456' });

      expect(response.status).toBe(200);
      expect(response.body.username).toBe('test');
      expect(response.body.userConfirmed).toBe(true);
    });

    it('should return RequestValidationError if confirmation code is invalid', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof ConfirmSignUpCommand) {
          return Promise.reject(
            new CodeMismatchException({
              message: 'Invalid confirmation code',
              $metadata: {},
            })
          );
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const error = RequestValidationError('Invalid confirmation code');

      const response = await request(app).post('/v1/auth/confirm').send({
        username: 'test',
        confirmationCode: 'my123',
      });

      expect(response.status).toBe(error.status);
      expect(response.body.code).toBe(error.code);
      expect(response.body.message).toBe(error.message);
    });
  });

  describe('GET /v1/auth/token', () => {
    it('should return 400 if username is missing in headers', async () => {
      const response = await request(app).get('/v1/auth/token');

      expect(response.status).toBe(400);
    });

    it('should return 200 if request is OK', async () => {
      (client.send as jest.Mock).mockImplementation((command) => {
        if (command instanceof AdminInitiateAuthCommand) {
          return Promise.resolve({
            AuthenticationResult: {
              AccessToken: 'test-access-token',
              ExpiresIn: 3600,
            },
          });
        }
        return Promise.reject(new Error('Unknown command'));
      });

      const current = now();
      const response = await request(app)
        .get('/v1/auth/token')
        .set('username', 'test')
        .set('authorization', 'Bearer test-refresh-token');

      expect(response.status).toBe(200);
      expect(response.body.accessToken).toBe('test-access-token');
      expect(response.body.expiry).toBe(current + 3600);
    });
  });
});
