import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma.service';
import { LocalStrategy } from 'src/lib/jwt/strategy/local.strategy';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from '../lib/jwt/strategy/jwt.strategy';

@Module({
  imports: [
    PassportModule,
    // JWTを使うための設定をしている
    JwtModule.registerAsync({
      useFactory: async (configService: ConfigService) => {
        return {
          // envファイルから秘密鍵を渡す
          secret: configService.get<string>('JWT_SECRET'),
          signOptions: {
            // 有効時間を設定
            // 指定する値は以下を参照
            // https://github.com/vercel/ms
            expiresIn: '1200s',
          },
        };
      },
      inject: [ConfigService], // useFactoryで使うためにConfigServiceを注入する
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, LocalStrategy, JwtStrategy],
  exports: [PassportModule],
})
export class AuthModule {}
