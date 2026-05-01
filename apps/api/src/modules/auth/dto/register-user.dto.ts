import { IsString, IsNotEmpty } from 'class-validator'

export class RegisterUserDto {
  @IsString()
  @IsNotEmpty()
  email!: string

  @IsString()
  @IsNotEmpty()
  name!: string

  @IsString()
  @IsNotEmpty()
  password!: string
}
