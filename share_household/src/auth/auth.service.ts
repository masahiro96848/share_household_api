import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { SignInUserDto } from './dto/sign-in-user.dto';
import { SignUpUserDto } from './dto/sign-up-user.dto';
import { Msg, Jwt } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * ユーザー新規登録
   * @param signUpDto
   * @returns
   */
  async signUp(signUpDto: SignUpUserDto): Promise<Msg> {
    const hashed = await bcrypt.hash(signUpDto.password, 12);
    try {
      await this.prisma.user.create({
        data: {
          nickname: signUpDto.nickname,
          email: signUpDto.email,
          password: hashed,
        },
      });
      return {
        message: 'ok',
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('This emial is already taken');
        }
      }
      throw error;
    }
  }

  /**
   * ユーザーログイン
   * @param signInDto
   */
  async login(signInDto: SignInUserDto): Promise<Jwt> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: signInDto.email,
      },
    });
    // ユーザーの情報がなかったらエラーを返す
    if (!user) throw new ForbiddenException('Email or password incorrect');
    const isValid = await bcrypt.compare(signInDto.password, user.password);
    if (!isValid) throw new ForbiddenException('Email or password incorrect');
    return this.generateJwt(user.id, user.email);
  }

  /**
   * Jwtを生成する関数
   * @param userId
   * @param email
   */
  async generateJwt(userId: number, email: string): Promise<Jwt> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '5m',
      secret: secret,
    });
    return {
      accessToken: token,
    };
  }
}
