import { ApiProperty } from '@nestjs/swagger';
import {
  IsNotEmpty,
  IsString,
  IsEmail,
  IsStrongPassword,
  MinLength,
  IsPhoneNumber,
  IsDateString,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ example: 'Sobir', description: 'Foydalanuvchi Ismi' })
  @IsNotEmpty()
  @IsString()
  first_name: string;

  @ApiProperty({ example: 'Karimov', description: 'Foydalanuvchi Familiyasi' })
  @IsNotEmpty()
  @IsString()
  last_name: string;

  @ApiProperty({ example: 'sobir123', description: 'Foydalanuvchi nomi' })
  @IsNotEmpty()
  @IsString()
  username: string;

  @ApiProperty({ example: 'password', description: 'Foydalanuvchi password' })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  @IsStrongPassword()
  password: string;

  @ApiProperty({
    example: 'confirm_password',
    description: 'Foydalanuvchi password',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  confirm_password: string;

  @ApiProperty({
    example: 'email1@mail.uz',
    description: 'Foydalanuvchi elektron pochtasi',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '+998901234567',
    description: 'Foydalanuvchi telefon raqami',
  })
  @IsPhoneNumber()
  phone: string;

  @ApiProperty({
    example: '01.01.2000',
    description: "Foydalanuvchi tug'ilgan sanasi",
  })
  @IsNotEmpty()
  @IsDateString()
  birthday: Date;
}
