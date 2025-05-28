import { Module } from '@nestjs/common';
import { EmailService } from './email.service';

@Module({
    providers: [EmailService],
    exports: [EmailService],
})
export class EmailModule {
    // Este módulo se encarga de enviar correos electrónicos de verificación.
    // Se puede extender para incluir más funcionalidades relacionadas con el correo electrónico.
}