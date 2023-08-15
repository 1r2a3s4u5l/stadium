import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/sequelize';
import { JwtService } from '@nestjs/jwt';
import { User } from './model/user.model';
import * as bcrypt from 'bcrypt';
import * as otpGenerator from 'otp-generator';
import { v4 as uuidv4, v4 } from 'uuid';
import { Response } from 'express';
import { LoginUserDto } from './dto/login-user.dto';
import { Op } from 'sequelize';
import { FindUserDto } from './dto/find-user.dto';
import { MailService } from '../mail/mail.service';
import { BotService } from '../bot/bot.service';
import { Otp } from '../otp/model/otp.model';
import { PhoneUserDto } from './dto/phone-user.dto';
import { AddMinutesToDate } from '../helpers/addMinutes';
import { dates, decode, encode } from '../helpers/crypto';
import { VerifyOtpDto } from './dto/verifyOtp.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User) private readonly userRepo: typeof User,
    @InjectModel(Otp) private readonly otpRepo: typeof Otp,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly botService: BotService,
  ) {}

  async registration(createUserDto: CreateUserDto, res: Response) {
    const user = await this.userRepo.findOne({
      where: { username: createUserDto.username },
    });
    if (user) {
      throw new BadRequestException('UserName already exists!');
    }
    if (createUserDto.password !== createUserDto.confirm_password) {
      throw new BadRequestException('Password is not match');
    }

    const hashed_password = await bcrypt.hash(createUserDto.password, 7);
    const newUser = await this.userRepo.create({
      ...createUserDto,
      hashed_password: hashed_password,
    });
    const tokens = await this.getTokens(newUser);

    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);
    const uniqueKey: string = uuidv4();
    const updatedUser = await this.userRepo.update(
      {
        hashed_refresh_token: hashed_refresh_token,
        activation_link: uniqueKey,
      },
      {
        where: { id: newUser.id },
        returning: true,
      },
    );
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });
    console.log(1);

    try {
      await this.mailService.sendUserConfirmation(updatedUser[1][0]);
    } catch (error) {
      console.log(error);
    }
    console.log(2);

    const response = {
      message: 'User registered',
      user: updatedUser[1][0],
      tokens,
    };

    return response;
  }

  async activate(link: string) {
    if (!link) {
      throw new BadRequestException('Activation link not found');
    }
    const updatedUser = await this.userRepo.update(
      { is_active: true },
      { where: { activation_link: link, is_active: false }, returning: true },
    );

    if (!updatedUser[1][0]) {
      throw new BadRequestException('User already activated');
    }
    const response = {
      message: 'User activated successfully',
      user: updatedUser,
    };
    return response;
  }

  async login(loginUserDto: LoginUserDto, res: Response) {
    const { email, password } = loginUserDto;
    const user = await this.userRepo.findOne({ where: { email } });
    if (!user) {
      throw new BadRequestException('User not registered');
    }
    if (!user.is_active) {
      throw new BadRequestException('user is not activated');
    }
    const isMatchPass = await bcrypt.compare(password, user.hashed_password);
    if (!isMatchPass) {
      throw new BadRequestException('User not registered(pass)');
    }
    const tokens = await this.getTokens(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);
    const updatedUser = await this.userRepo.update(
      {
        hashed_refresh_token: hashed_refresh_token,
      },
      {
        where: { id: user.id },
        returning: true,
      },
    );
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });

    const response = {
      message: 'User logged in',
      user: updatedUser[1][0],
      tokens,
    };
    return response;
  }

  async logout(refreshToken: string, res: Response) {
    const userData = await this.jwtService.verify(refreshToken, {
      secret: process.env.REFRESH_TOKEN_KEY,
    });
    if (!userData) {
      throw new ForbiddenException('User not found');
    }
    const updatedUser = await this.userRepo.update(
      {
        hashed_refresh_token: null,
      },
      {
        where: { id: userData.id },
        returning: true,
      },
    );
    res.clearCookie('refresh_token');
    const response = {
      message: 'User logged out successfuly',
      user: updatedUser[1][0],
    };
    return response;
  }

  async refreshToken(user_id: number, refreshToken: string, res: Response) {
    const decodedToken = this.jwtService.decode(refreshToken);
    console.log(decodedToken);

    if (user_id != decodedToken['id']) {
      throw new BadRequestException('user not found');
    }
    const user = await this.userRepo.findOne({ where: { id: user_id } });
    if (!user || !user.hashed_refresh_token) {
      throw new BadRequestException('user not found');
    }

    const tokentMatch = await bcrypt.compare(
      refreshToken,
      user.hashed_refresh_token,
    );

    if (!tokentMatch) {
      throw new ForbiddenException('Forbidden');
    }

    const tokens = await this.getTokens(user);
    const hashed_refresh_token = await bcrypt.hash(tokens.refresh_token, 7);
    const updatedUser = await this.userRepo.update(
      {
        hashed_refresh_token: hashed_refresh_token,
      },
      {
        where: { id: user.id },
        returning: true,
      },
    );
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: 15 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    });
    const response = {
      message: 'User refreshed',
      user: updatedUser[1][0],
      tokens,
    };
    return response;
  }

  async findAll(findUserDto: FindUserDto) {
    const where = {};
    if (findUserDto.first_name) {
      where['first_name'] = {
        [Op.like]: `%${findUserDto.first_name}%`,
      };
    }
    if (findUserDto.last_name) {
      where['last_name'] = {
        [Op.like]: `%${findUserDto.last_name}%`,
      };
    }
    if (findUserDto.birthday_begin && findUserDto.birthday_end) {
      where[Op.and] = {
        birthday: {
          [Op.between]: [findUserDto.birthday_begin, findUserDto.birthday_end],
        },
      };
    } else if (findUserDto.birthday_begin) {
      where['birthday'] = { [Op.gte]: findUserDto.birthday_begin };
    } else if (findUserDto.birthday_end) {
      where['birthday'] = { [Op.lte]: findUserDto.birthday_end };
    }
    const users = await User.findAll({ where });
    if (!users) {
      throw new BadRequestException('user not found');
    }
    return users;
  }

  async newOtp(phoneUserDto: PhoneUserDto) {
    const phone_number = phoneUserDto.phone;
    const otp = otpGenerator.generate(4, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });

    const isSend = await this.botService.sendOTP(phone_number, otp);
    if (!isSend) {
      throw new HttpException(
        "Avval Botdan ro'yxatdan o'ting",
        HttpStatus.BAD_REQUEST,
      );
    }
    const now = new Date();
    const expiration_time = AddMinutesToDate(now, 5);

    await this.otpRepo.destroy({
      where: { check: phone_number },
    });
    const newOtp = await this.otpRepo.create({
      id: v4(),
      otp,
      expiration_time,
      check: phone_number,
    });

    const details = {
      timestamp: now,
      check: phone_number,
      success: true,
      message: 'OTP send to user',
      otp_id: newOtp.id,
    };
    const encoded = await encode(JSON.stringify(details));
    return { status: 'Success', Details: encoded };
  }

  async verifyOtp(verifyOtpDto: VerifyOtpDto) {
    const { verification_key, otp, check } = verifyOtpDto;
    const currantdate = new Date();
    const decoded = await decode(verification_key);
    const obj = JSON.parse(decoded);
    const check_obj = obj.check;
    if (check_obj != check) {
      throw new BadRequestException('OTP bu raqamga yuborilmagan');
    }
    const result = await this.otpRepo.findOne({
      where: { id: obj.otp_id },
    });
    if (result != null) {
      if (!result.verified) {
        if (dates.compare(result.expiration_time, currantdate)) {
          if (otp === result.otp) {
            const user = await this.userRepo.findOne({
              where: { phone: check },
            });
            if (user) {
              const updatedUser = await this.userRepo.update(
                { is_owner: true },
                { where: { id: user.id }, returning: true },
              );
              await this.otpRepo.update(
                { verified: true },
                { where: { id: obj.otp_id }, returning: true },
              );


              const response = {
                message: 'User update as owner',
                user: updatedUser[1][0],
              };
              return response;
            } else {
              throw new BadRequestException("Bunday foydalanuvchi yo'q");
            }
          } else {
            throw new BadRequestException('OTP is not match');
          }
        } else {
          throw new BadRequestException('OTP expired');
        }
      } else {
        throw new BadRequestException('OTP already used');
      }
    } else {
      throw new BadRequestException("Bunday foydalanuvchi yo'q");
    }
  }

  async getTokens(user: User) {
    const jwtPayload = {
      id: user.id,
      is_active: user.is_active,
      is_owner: user.is_owner,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }
}
