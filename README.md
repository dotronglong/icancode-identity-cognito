# icancode-identity-cognito

An identity module based on `@icancode/express` to integrate with AWS Cognito.

# How to use

- Add package as dependency

```bash
yarn add @icancode/identity-cognito
```

- Register the module

```typescript
import { ModuleLoader } from '@icancode/express';
import IdentityCognito from '@icancode/identity-cognito';

const loader = new ModuleLoader(app);
loader.register(IdentityCognito);
```

# Environment variables

## Mandatory

| Name                        | Description                                                     |
| --------------------------- | --------------------------------------------------------------- |
| COGNITO_ADMIN_CLIENT_ID     | Cognito admin client id                                         |
| COGNITO_ADMIN_CLIENT_SECRET | Cognito admin client secret                                     |
| COGNITO_POOL_ID             | Cognito Pool id                                                 |
| JWT_RSA_KEY                 | Path to RSA private key (use for self-managed JWT token)        |
| JWT_RSA_PUBLIC              | Path to RSA public key (use for self-managed JWT token)         |
| JWT_EXPIRES_IN              | Expiration of token in seconds (use for self-managed JWT token) |

## Enable social integration

| Name                  | Description                                      |
| --------------------- | ------------------------------------------------ |
| COGNITO_CLIENT_ID     | Cognito client id (use for exchanging token)     |
| COGNITO_CLIENT_SECRET | Cognito client secret (use for exchanging token) |
| COGNITO_DOMAIN        | Cognito domain (use for exchanging token)        |
| COGNITO_REDIRECT_URI  | Cognito redirect uri (use for exchanging token)  |
