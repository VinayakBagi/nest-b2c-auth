import {
  Controller,
  Post,
  Res,
  Body,
  Header,
  Get,
  Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('callback/azure-ad-b2c')
  @Header('Content-Type', 'text/html')
  async postAzureB2CCallback(@Query() query: any) {
    console.log('Received auth callback:', {
      hasCode: !!query.code,
      hasState: !!query.state,
      needsTokenExchange: query.needsTokenExchange,
      frontendNote: query.frontendNote,
    });

    try {
      // Use the new handleAuthCallback method
      const result = await this.authService.handleAuthCallback(query);

      if (result.success) {
        console.log(
          'Authentication successful for user:',
          result.userInfo?.email,
        );
      } else {
        console.warn('Authentication failed:', result.message || result.error);
      }

      return result;
    } catch (error) {
      console.error('Auth callback error:', error);
      return {
        success: false,
        error: 'Internal server error during authentication',
        redirectUrl:
          process.env.FRONTEND_REDIRECT_URL || 'http://localhost:3000',
      };
    }
  }

  @Get('callback/azure-ad-b2c')
  @Header('Content-Type', 'text/html')
  async handleAzureB2CCallback(@Query() query: any) {
    console.log('Received auth callback:', {
      hasCode: !!query.code,
      hasState: !!query.state,
      needsTokenExchange: query.needsTokenExchange,
      frontendNote: query.frontendNote,
    });

    try {
      // Use the new handleAuthCallback method
      const result = await this.authService.handleAuthCallback(query);

      if (result.success) {
        console.log(
          'Authentication successful for user:',
          result.userInfo?.email,
        );
      } else {
        console.warn('Authentication failed:', result.message || result.error);
      }

      return result;
    } catch (error) {
      console.error('Auth callback error:', error);
      return {
        success: false,
        error: 'Internal server error during authentication',
        redirectUrl:
          process.env.FRONTEND_REDIRECT_URL || 'http://localhost:3000',
      };
    }
  }
}
