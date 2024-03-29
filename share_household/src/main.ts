import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');
  // CORS対応
  app.enableCors({
    credentials: true,
    origin: ['http://localhost:3000', 'http://localhost'],
  });

  await app.listen(3000);
}
bootstrap();
