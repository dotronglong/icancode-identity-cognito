import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { CognitoJwtVerifierSingleUserPool } from 'aws-jwt-verify/cognito-verifier';
import { CognitoAccessTokenPayload } from 'aws-jwt-verify/jwt-model';
import {
  AdminInitiateAuthResponse,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import * as crypto from 'crypto';
import { env } from './env';
import { UnsupportedOperationError } from '@icancode/base';
import { decodeJwt } from 'jose';
import { signRSA } from './jwt';
import { now } from './time';

interface CognitoJwtVerifierSingleUserPoolProperties {
  userPoolId: string;
  tokenUse: 'access';
  clientId: string;
}

interface AuthenticationResult {
  accessToken?: string;
  refreshToken?: string;
  expiresIn?: number;
}

interface TokenRequest {
  username: string;
}

interface TokenResponse {
  accessToken: string;
  expiry: number;
  refreshToken?: string;
}

interface ExchangeTokenResponse {
  access_token: string;
  id_token: string;
  refresh_token: string;
  expires_in: number;
}

class Cognito {
  public readonly clientId: string;
  public readonly clientSecret: string;
  public readonly userPoolId: string;
  public readonly client: CognitoIdentityProviderClient;

  // eslint-disable-next-line
  private accessTokenVerifier!: CognitoJwtVerifierSingleUserPool<CognitoJwtVerifierSingleUserPoolProperties>;

  constructor() {
    this.clientId = env.COGNITO_ADMIN_CLIENT_ID;
    this.clientSecret = env.COGNITO_ADMIN_CLIENT_SECRET;
    this.userPoolId = env.COGNITO_POOL_ID;
    this.client = new CognitoIdentityProviderClient({});
  }

  checkPrerequisites() {
    if (this.clientId.length === 0) {
      throw new Error('COGNITO_ADMIN_CLIENT_ID is missing');
    } else if (this.clientSecret.length === 0) {
      throw new Error('COGNITO_ADMIN_CLIENT_SECRET is missing');
    } else if (this.userPoolId.length === 0) {
      throw new Error('COGNITO_POOL_ID is missing');
    }

    if (!env.COGNITO_USE_JWT) {
      this.accessTokenVerifier = CognitoJwtVerifier.create({
        userPoolId: this.userPoolId,
        tokenUse: 'access',
        clientId: this.clientId,
      });
    }
  }

  getSecretHash(username: string): string {
    return crypto
      .createHmac('SHA256', this.clientSecret)
      .update(username + this.clientId)
      .digest('base64');
  }

  async verifyAccessToken(
    accessToken: string
  ): Promise<CognitoAccessTokenPayload> {
    return this.accessTokenVerifier.verify(accessToken);
  }

  async generateTokenResponse(
    request: TokenRequest,
    result: AdminInitiateAuthResponse | ExchangeTokenResponse
  ): Promise<TokenResponse> {
    const data: AuthenticationResult | undefined =
      this.toAuthenticationResult(result);
    if (!data || !data.accessToken) {
      throw UnsupportedOperationError;
    }

    let response: TokenResponse;
    if (env.COGNITO_USE_JWT) {
      const decodedPayload = decodeJwt(data.accessToken);
      const expiresIn = env.JWT_EXPIRES_IN;
      const accessToken = await signRSA(
        {
          username: request.username,
          sub: decodedPayload.sub,
        },
        {
          expiresIn,
        }
      );
      response = {
        accessToken: accessToken,
        expiry: now() + expiresIn,
      };
    } else {
      response = {
        accessToken: data.accessToken,
        expiry: now() + (data.expiresIn || 3600),
      };
    }

    if (data.refreshToken) {
      response.refreshToken = data.refreshToken;
    }

    return response;
  }

  private isAdminInitiateAuthResponse(
    result: any
  ): result is AdminInitiateAuthResponse {
    return (
      result.AuthenticationResult !== undefined &&
      typeof result.AuthenticationResult.AccessToken === 'string'
    );
  }

  private isExchangeTokenResponse(
    result: any
  ): result is ExchangeTokenResponse {
    return (
      result.access_token !== undefined &&
      typeof result.access_token === 'string'
    );
  }

  private toAuthenticationResult(
    result: AdminInitiateAuthResponse | ExchangeTokenResponse
  ): AuthenticationResult | undefined {
    if (
      this.isAdminInitiateAuthResponse(result) &&
      result.AuthenticationResult
    ) {
      const { AccessToken, ExpiresIn, RefreshToken } =
        result.AuthenticationResult;
      return {
        accessToken: AccessToken,
        expiresIn: ExpiresIn,
        refreshToken: RefreshToken,
      };
    } else if (this.isExchangeTokenResponse(result)) {
      const { access_token, refresh_token, expires_in } = result;

      return {
        accessToken: access_token,
        refreshToken: refresh_token,
        expiresIn: expires_in,
      };
    }
  }
}

export default new Cognito();
