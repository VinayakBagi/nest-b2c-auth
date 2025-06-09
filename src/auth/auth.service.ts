import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly httpService: HttpService, // Make sure to inject HttpService
  ) {}

  /**
   * Exchange authorization code for tokens and extract user information
   */
  async exchangeCodeForUserInfo(code: string): Promise<any> {
    try {
      this.logger.log('Starting authorization code exchange...');

      // Step 1: Exchange authorization code for tokens
      const tokenResponse = await this.exchangeAuthorizationCode(code);

      // Step 2: Extract user information from ID token
      const userInfo = await this.extractUserInfoFromIdToken(
        tokenResponse.id_token,
      );

      this.logger.log('Successfully extracted user info:', {
        email: userInfo.email,
        name: userInfo.name,
      });

      return {
        userInfo,
        tokens: tokenResponse,
      };
    } catch (error) {
      this.logger.error('Error in code exchange:', error);
      throw new Error(
        `Failed to exchange code for user info: ${error.message}`,
      );
    }
  }

  /**
   * Exchange authorization code for access token and ID token
   */
  private async exchangeAuthorizationCode(code: string): Promise<any> {
    const tenant = process.env.AZURE_B2C_TENANT_NAME;
    const policy = process.env.AZURE_B2C_USER_FLOW;
    const clientId = process.env.AZURE_B2C_CLIENT_ID;
    const clientSecret = process.env.AZURE_B2C_CLIENT_SECRET; // You'll need this
    const redirectUri =
      process.env.AZURE_B2C_REDIRECT_URI ||
      'http://localhost:3000/api/auth/callback/azure-ad-b2c';

    const tokenEndpoint = `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/${policy}/oauth2/v2.0/token`;

    const tokenRequest: any = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'openid profile email',
    };

    this.logger.log('Exchanging code at endpoint:', tokenEndpoint);

    try {
      const response = await firstValueFrom(
        this.httpService.post(
          tokenEndpoint,
          new URLSearchParams(tokenRequest),
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
          },
        ),
      );

      this.logger.log('Token exchange successful');
      return response.data;
    } catch (error) {
      this.logger.error('Token exchange failed:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        endpoint: tokenEndpoint,
      });

      if (error.response?.status === 400) {
        throw new Error('Invalid authorization code or client configuration');
      }

      throw new Error(`Token exchange failed: ${error.message}`);
    }
  }

  /**
   * Extract user information from ID token
   */
  private async extractUserInfoFromIdToken(idToken: string): Promise<any> {
    try {
      // First decode without verification to see the structure
      const decoded = jwt.decode(idToken, { complete: true }) as any;
      this.logger.log('ID Token structure:', {
        header: decoded?.header,
        payloadKeys: decoded?.payload ? Object.keys(decoded.payload) : [],
      });

      // Verify and decode the ID token
      const verifiedPayload = await this.verifyAzureIdToken(idToken);

      // Extract user information from various possible claim names
      const userInfo = {
        email: this.extractEmail(verifiedPayload),
        name: this.extractName(verifiedPayload),
        displayName: verifiedPayload.displayName || verifiedPayload.name,
        givenName: verifiedPayload.given_name,
        surname: verifiedPayload.family_name,
        userId: verifiedPayload.oid || verifiedPayload.sub,
        tenantId: verifiedPayload.tid,
        // Include all available claims for debugging
        allClaims: verifiedPayload,
      };

      this.logger.log('Extracted user information:', {
        email: userInfo.email,
        name: userInfo.name,
        userId: userInfo.userId,
        availableClaims: Object.keys(verifiedPayload),
      });

      return userInfo;
    } catch (error) {
      this.logger.error('Failed to extract user info from ID token:', error);
      throw new Error(`Failed to extract user info: ${error.message}`);
    }
  }

  /**
   * Extract email from various possible claim sources
   */
  private extractEmail(payload: any): string | undefined {
    const emailSources = [
      payload.email,
      payload.emails?.[0],
      payload['signInNames.emailAddress'],
      payload.upn,
      payload.preferred_username,
      payload.unique_name,
    ];

    for (const email of emailSources) {
      if (email && this.isValidEmail(email)) {
        return email;
      }
    }

    this.logger.warn(
      'No valid email found in token claims:',
      Object.keys(payload),
    );
    return undefined;
  }

  /**
   * Extract name from various possible claim sources
   */
  private extractName(payload: any): string | undefined {
    return (
      payload.name ||
      payload.displayName ||
      payload.given_name ||
      `${payload.given_name || ''} ${payload.family_name || ''}`.trim() ||
      payload.preferred_username ||
      'Unknown'
    );
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Your existing method - enhanced with better error handling
   */
  async verifyAzureIdToken(idToken: string): Promise<any> {
    const tenant = process.env.AZURE_B2C_TENANT_NAME;
    const policy = process.env.AZURE_B2C_USER_FLOW;
    const jwksUri = `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/${policy}/discovery/v2.0/keys`;

    try {
      const client = jwksClient({ jwksUri });
      const decodedHeader = jwt.decode(idToken, { complete: true }) as any;

      if (!decodedHeader?.header?.kid) {
        throw new Error('Invalid ID token: missing key ID in header');
      }

      const key = await client.getSigningKey(decodedHeader.header.kid);
      const publicKey = key.getPublicKey();

      const verifiedPayload = jwt.verify(idToken, publicKey);
      this.logger.log('ID token verification successful');

      return verifiedPayload;
    } catch (error) {
      this.logger.error('ID token verification failed:', error);
      throw new Error(`ID token verification failed: ${error.message}`);
    }
  }

  /**
   * Your existing method - unchanged
   */
  issueCustomJwt(user: any): string {
    const payload = {
      sub: user.sub || user.userId,
      email: user.email,
      name: user.name,
    };
    return this.jwtService.sign(payload);
  }

  /**
   * Handle the complete authentication flow
   */
  async handleAuthCallback(authData: any): Promise<any> {
    try {
      // Check if we need to exchange authorization code
      if (authData.needsTokenExchange === 'true' && authData.code) {
        this.logger.log('Handling authorization code exchange...');

        const result = await this.exchangeCodeForUserInfo(authData.code);

        // Issue your custom JWT
        const customToken = this.issueCustomJwt(result.userInfo);

        return {
          success: true,
          userInfo: result.userInfo,
          customToken: customToken,
          redirectUrl:
            process.env.FRONTEND_REDIRECT_URL || 'http://localhost:3000',
        };
      } else {
        // Handle other authentication scenarios
        this.logger.log('No token exchange needed or code missing');
        return {
          success: false,
          message:
            'No authorization code provided or token exchange not needed',
          redirectUrl:
            process.env.FRONTEND_REDIRECT_URL || 'http://localhost:3000',
        };
      }
    } catch (error) {
      this.logger.error('Auth callback handling failed:', error);
      return {
        success: false,
        error: error.message,
        redirectUrl:
          process.env.FRONTEND_REDIRECT_URL || 'http://localhost:3000',
      };
    }
  }
}
