import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { PrismaService } from 'src/prisma.service';
import { JwtPayload } from 'src/lib/jwt/interfaces/JwtPayload';
import { ResponseUserType } from 'src/interfaces/User';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private readonly jwtSecret: JwtService,
  ) {}

  /**
   * ログイン
   * @param loginUserDto
   */
  async login(loginUserDto: LoginUserDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        email: loginUserDto.email,
      },
    });
    if (
      !user ||
      !(await bcrypt.compare(loginUserDto.password, user.password))
    ) {
      throw new UnauthorizedException(
        'メールアドレスまたはパスワードが違います。',
      );
    }
    const resUser: ResponseUserType = {
      id: user.id,
      nickname: user.nickname,
      email: user.email,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
    };

    // jwtアクセストークンを作成して返却
    return {
      user: resUser,
      accessToken: this.jwtSecret.sign(payload),
    };
  }

  /**
   * 新規登録
   * @param registerUserDto
   */
  async register(registerUserDto: RegisterUserDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        email: registerUserDto.email,
      },
    });

    // メールアドレス確認
    if (!!user)
      throw new UnauthorizedException(
        `${registerUserDto.email} は別のアカウントで使用されています。`,
      );

    const hashPassword = await bcrypt.hash(registerUserDto.password, 10);
    const createdUser = await this.prisma.user.create({
      data: {
        nickname: registerUserDto.nickname,
        email: registerUserDto.email,
        password: hashPassword,
      },
    });

    const resUser: ResponseUserType = {
      id: createdUser.id,
      nickname: createdUser.nickname,
      email: createdUser.email,
      createdAt: createdUser.createdAt,
      updatedAt: createdUser.updatedAt,
    };

    const payload: JwtPayload = {
      userId: createdUser.id,
      email: createdUser.email,
    };

    // jwtアクセストークンを作成し返却
    return {
      user: resUser,
      accessToken: this.jwtSecret.sign(payload),
    };
  }

  /**
   *  認証チェック
   * @param userId
   * @returns
   */
  async authCheck(userId: number) {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user) throw new UnauthorizedException('認証データが存在しません');

    const resUser: ResponseUserType = {
      id: user.id,
      nickname: user.nickname,
      email: user.email,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
    };

    // jwtアクセストークンを作成し返却
    return {
      user: resUser,
      accessToken: this.jwtSecret.sign(payload),
    };
  }
}
