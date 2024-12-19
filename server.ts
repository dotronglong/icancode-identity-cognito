import { createDebug } from '@icancode/base';
import { createApp } from './test/bootstrap';

createApp().then((app) => {
  const port = 5555;
  const debug = createDebug('app');
  app.listen(port, () => debug('Server is ready at port', port));
});
