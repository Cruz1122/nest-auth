import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";   

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  // Este guardia se utiliza para proteger las rutas que requieren autenticación JWT.
  // Extiende de AuthGuard de Passport, que maneja la validación del token JWT.
  // No es necesario agregar lógica adicional aquí, ya que la validación se maneja automáticamente.
}