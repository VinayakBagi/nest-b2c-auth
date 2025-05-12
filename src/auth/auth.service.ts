import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  async verifyAzureIdToken(idToken: string): Promise<any> {
    const tenant = process.env.AZURE_B2C_TENANT_NAME;
    const policy = process.env.AZURE_B2C_USER_FLOW;
    const jwksUri = `https://${tenant}.b2clogin.com/${tenant}.onmicrosoft.com/${policy}/discovery/v2.0/keys`;

    const client = jwksClient({ jwksUri });
    const decodedHeader = jwt.decode(idToken, { complete: true }) as any;
    const key = await client.getSigningKey(decodedHeader.header.kid);
    const publicKey = key.getPublicKey();

    return jwt.verify(idToken, publicKey);
  }

  issueCustomJwt(user: any): string {
    const payload = {
      sub: user.sub,
      email: user.email,
      name: user.name,
    };
    return this.jwtService.sign(payload);
  }
}