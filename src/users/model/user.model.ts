import { ApiProperty } from '@nestjs/swagger';
import { Column, DataType, Table, Model } from 'sequelize-typescript';

interface UserAttrs {
  first_name: string;
  last_name: string;
  username: string;
  hashed_password: string;
  telegram_link: string;
  email: string;
  phone: string;
  user_photo: string;
  birthday: Date;
  is_owner: boolean;
  is_active: boolean;
  hashed_refresh_token: string;
}

@Table({ tableName: 'users' })
export class User extends Model<User, UserAttrs> {
  @ApiProperty({ example: 1, description: 'Unique ID' })
  @Column({
    type: DataType.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  })
  id: number;

  @ApiProperty({ example: 'Sobir', description: 'Foydalanuvchi Ismi' })
  @Column({
    type: DataType.STRING,
  })
  first_name: string;

  @ApiProperty({ example: 'Karimov', description: 'Foydalanuvchi Familiyasi' })
  @Column({
    type: DataType.STRING,
  })
  last_name: string;

  @ApiProperty({ example: 'sobir123', description: 'Foydalanuvchi nomi' })
  @Column({
    type: DataType.STRING,
    unique: true,
  })
  username: string;

  @ApiProperty({
    example: 'telegram_link',
    description: 'Foydalanuvchi telegram',
  })
  @Column({
    type: DataType.STRING,
  })
  telegram_link: string;

  @ApiProperty({ example: 'password', description: 'Foydalanuvchi password' })
  @Column({
    type: DataType.STRING,
  })
  hashed_password: string;

  @ApiProperty({
    example: 'email1@mail.uz',
    description: 'Foydalanuvchi elektron pochtasi',
  })
  @Column({
    type: DataType.STRING,
    unique: true,
  })
  email: string;

  @ApiProperty({
    example: '+998901234567',
    description: 'Foydalanuvchi telefon raqami',
  })
  @Column({
    type: DataType.STRING,
  })
  phone: string;

  @ApiProperty({
    example: 'image.png | image.jpg | image.jpeg',
    description: 'Foydalanuvchi rasmi',
  })
  @Column({
    type: DataType.STRING,
  })
  user_photo: string;
  @ApiProperty({
    example: '01.01.2000',
    description: "Foydalanuvchi tug'ilgan sanasi",
  })
  @Column({
    type: DataType.DATE,
  })
  birthday: Date;

  @ApiProperty({
    example: 'false | true',
    description: "Maydon egasi yoki yo'qligi",
  })
  @Column({
    type: DataType.BOOLEAN,
    defaultValue: false,
  })
  is_owner: Boolean;

  @ApiProperty({
    example: 'false | true',
    description: 'Foydalanuvchi tastiqlangan holati',
  })
  @Column({
    type: DataType.BOOLEAN,
    defaultValue: false,
  })
  is_active: Boolean;

  @ApiProperty({ example: 'token', description: 'Foydalanuvchi tokeni' })
  @Column({
    type: DataType.STRING,
  })
  hashed_refresh_token: string;

  @Column({
    type: DataType.STRING,
  })
  activation_link: string;
}
