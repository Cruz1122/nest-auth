import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
    private transporter;
    private appName: string;
    private appURL: string;

    constructor(private configService: ConfigService) {
        this.transporter = nodemailer.createTransport({
            host: this.configService.get('EMAIL_HOST'),
            port: this.configService.get('EMAIL_PORT'),
            secure: this.configService.get('EMAIL_SECURE') === 'true',
            auth: {
                user: this.configService.get('EMAIL_USER'),
                pass: this.configService.get('EMAIL_PASSWORD'),
            },
        });

        this.appName = this.configService.get('APP_NAME') || 'Backend UAM';
        this.appURL = this.configService.get('APP_URL') || 'https://backend-uam.com';
    }

    async sendVerificationEmail(
        email: string,
        name: string,
        code: string,
    ): Promise<void> {
        const mailOptions = {
            from: `"${this.appName}" <${this.configService.get('EMAIL_USER')}>`,
            to: email,
            subject: 'Verifica tu dirección de correo electrónico',
            html: this.getVerificationEmailTemplate(name, code),
        };

        await this.transporter.sendMail(mailOptions);
    }

    private getVerificationEmailTemplate(name: string, code: string): string {
        return `<DOCTYPE html> ...`; // Aquí sigue el contenido HTML
    }
}
