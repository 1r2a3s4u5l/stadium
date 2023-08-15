import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Res,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';
import { User } from './model/user.model';
import { Response } from 'express';
import { LoginUserDto } from './dto/login-user.dto';
import { CookieGetter } from '../decorators/cookieGetter.decorator';
import { FindUserDto } from './dto/find-user.dto';
import { UserGuard } from '../guards/user.guard';
import { PhoneUserDto } from './dto/phone-user.dto';
import { VerifyOtpDto } from './dto/verifyOtp.dto';
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'register User' })
  @ApiResponse({ status: 201, type: User })
  @Post('signup')
  registration(
    @Body() createUserDto: CreateUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.usersService.registration(createUserDto, res);
  }

  // @UseGuards(UserGuard)
  @ApiOperation({ summary: 'login User' })
  @ApiResponse({ status: 200, type: User })
  @HttpCode(HttpStatus.OK)
  @Post('signin')
  login(
    @Body() loginUserDto: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.usersService.login(loginUserDto, res);
  }

  @ApiOperation({ summary: 'logout User' })
  @ApiResponse({ status: 200, type: User })
  @HttpCode(HttpStatus.OK)
  @Post('signout')
  logout(
    @CookieGetter('refresh_token') refreshToken: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.usersService.logout(refreshToken, res);
  }

  @Post(':id/refresh')
  refresh(
    @Param('id') id: string,
    @CookieGetter('refresh_token') refreshToken: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.usersService.refreshToken(+id, refreshToken, res);
  }

  @Post('find')
  findAll(@Body() findUserDto: FindUserDto) {
    return this.usersService.findAll(findUserDto);
  }

  @Post('/otp')
  newOtp(@Body() phoneUserDto: PhoneUserDto) {
    return this.usersService.newOtp(phoneUserDto);
  }

  @Post('/verify')
  verify(@Body() verifyOtpDto: VerifyOtpDto) {
    return this.usersService.verifyOtp(verifyOtpDto);
  }

  @ApiOperation({ summary: 'activated user' })
  @ApiResponse({ status: 200, type: [User] })
  @Get('activate/:link')
  activate(@Param('link') link: string) {
    return this.usersService.activate(link);
  }
}
