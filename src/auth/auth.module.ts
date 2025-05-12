import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [
    JwtModule.register({
      secret: 'your_jwt_secret_here',
      signOptions: { expiresIn: '1h' },
    }),
    HttpModule,
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}