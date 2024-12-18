import { bool, cleanEnv, num, str } from 'envalid';

export const env = cleanEnv(process.env, {
  COGNITO_ADMIN_CLIENT_ID: str(),
  COGNITO_ADMIN_CLIENT_SECRET: str(),
  COGNITO_POOL_ID: str(),

  COGNITO_USE_JWT: bool({ default: false }),
  JWT_RSA_KEY: str({ default: '' }),
  JWT_RSA_PUBLIC: str({ default: '' }),
  JWT_EXPIRES_IN: num({ default: 3600 }),

  COGNITO_USE_PROVIDER: bool({ default: false }),
  COGNITO_CLIENT_ID: str({ default: '' }),
  COGNITO_CLIENT_SECRET: str({ default: '' }),
  COGNITO_DOMAIN: str({ default: '' }),
  COGNITO_REDIRECT_URI: str({ default: '' }),
});
