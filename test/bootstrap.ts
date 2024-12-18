import { handleError, ModuleLoader } from '@icancode/express';
import express from 'express';
import IdentityCognito from '../src/index';

export async function createApp(): Promise<express.Express> {
  const app = express();
  app.use(express.json());
  const loader = new ModuleLoader(app);
  loader.register(IdentityCognito);
  await loader.load('IdentityCognito');
  app.use(handleError);

  return app;
}
