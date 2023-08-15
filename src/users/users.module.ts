import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { SequelizeModule } from '@nestjs/sequelize';
import { User } from './model/user.model';
import { JwtModule } from '@nestjs/jwt';
import { MailModule } from '../mail/mail.module';
import { BotModule } from '../bot/bot.module';
import { OtpModule } from '../otp/otp.module';
import { Otp } from '../otp/model/otp.model';

@Module({
  imports: [
    SequelizeModule.forFeature([User, Otp]),
    JwtModule.register({}),
    MailModule,
    BotModule,
    OtpModule,
  ],
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
