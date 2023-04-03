import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { SignInUserDto } from './dto/sign-in-user.dto';
import { SignUpUserDto } from './dto/sign-up-user.dto';
import { PrismaService } from 'src/prisma.service';
import { ResponseUserType } from 'src/interfaces/User';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private readonly jwtSecret: JwtService,
  ) {}

  /**
   * ログイン
   * @param signInUserDto
   */
  async signIn(signInUserDto: SignInUserDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        email: signInUserDto.email,
      },
    });
    if (
      !user ||
      !(await bcrypt.compare(signInUserDto.password, user.password))
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
  }

  async signUp(signUpUserDto: SignUpUserDto) {
    const user = await this.prisma.user.findFirst({
      where: {
        email: signUpUserDto.email,
      },
    });

    // メールアドレス確認
    if (!!user)
      throw new UnauthorizedException(
        `${signUpUserDto.email} は別のアカウントで使用されています。`,
      );

    const hashPassword = await bcrypt.hash(signUpUserDto.password, 10);
    const createdUser = await this.prisma.user.create({
      data: {
        nickname: signUpUserDto.nickname,
        email: signUpUserDto.email,
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
  }
}
