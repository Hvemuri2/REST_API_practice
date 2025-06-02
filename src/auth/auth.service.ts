import { ForbiddenException, Injectable } from "@nestjs/common"
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "generated/prisma/runtime/library";
import { JwtService } from "@nestjs/jwt";

@Injectable({})
export class AuthService{
    constructor(private prisma: PrismaService, private jwt: JwtService){}

    async login(dto: AuthDto){
        const user = 
        await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            }
        });

        if(!user) 
            throw new ForbiddenException(
            'incorrect user',
            );
        
        const pwMatches = await argon.verify(
            user.hash,
            dto.password,
        );

        if (!pwMatches)
            throw new ForbiddenException(
                'pasword incorrect',
            );

        const { hash, ...userWithoutHash } = user; // temp solution
        return userWithoutHash;

    }

    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password);

        try{
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
                select: { // temp solution
                    id: true,
                    createdAt: true,
                    updatedAt: true,
                    email: true,
                    firstName: true,
                    lastName: true
                },
            });
            return user;
        }catch(error){
            if (error instanceof PrismaClientKnownRequestError){
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken',);
                }
            }

        }
    }

    async signToken(
        userID: number,
        email: string,
    ) {}
} 