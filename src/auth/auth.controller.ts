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

  @Get('callback/azure-ad-b2c')
  async getRedirectDebug(@Query() query: any) {
    const fragmentData = query;
    console.log('Fragment Data:', fragmentData);

    return { redirectUrl: `http://localhost:3000/dashboard` };
  }
}
