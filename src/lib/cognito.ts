import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { CognitoJwtVerifierSingleUserPool } from 'aws-jwt-verify/cognito-verifier';
import { CognitoAccessTokenPayload } from 'aws-jwt-verify/jwt-model';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import * as crypto from 'crypto';

interface CognitoJwtVerifierSingleUserPoolProperties {
  userPoolId: string;
  tokenUse: 'access';
  clientId: string;
}

class Cognito {
  public readonly clientId: string;
  public readonly clientSecret: string;
  public readonly userPoolId: string;
  public readonly client: CognitoIdentityProviderClient;

  // eslint-disable-next-line
  private accessTokenVerifier!: CognitoJwtVerifierSingleUserPool<CognitoJwtVerifierSingleUserPoolProperties>;

  constructor() {
    this.clientId = process.env.COGNITO_ADMIN_CLIENT_ID || '';
    this.clientSecret = process.env.COGNITO_ADMIN_CLIENT_SECRET || '';
    this.userPoolId = process.env.COGNITO_POOL_ID || '';
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

    this.accessTokenVerifier = CognitoJwtVerifier.create({
      userPoolId: this.userPoolId,
      tokenUse: 'access',
      clientId: this.clientId,
    });
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
}

export default new Cognito();
