import { Express } from 'express';
import { ModuleBuilder } from '@icancode/express';
import cognito from './lib/cognito';
import { getAuthV1Router } from './handler/AuthV1';

export * from './lib/header';
export * from './lib/jwt';

export default ModuleBuilder.builder('IdentityCognito')
  .withInstaller(async (app: Express): Promise<void> => {
    cognito.checkPrerequisites();
    app.use('/v1/auth', getAuthV1Router());
  })
  .build();
