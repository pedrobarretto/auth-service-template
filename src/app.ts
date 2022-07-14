import express, { Response, Request } from 'express';
import session from 'express-session';

import { userApp } from './apps/UserApp';
import { checkUserCredentials } from './middlewares/UserMiddleware';
import { connect } from './mongo';

const app = express();

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
  })
);

app.post(
  '/register',
  checkUserCredentials,
  async (req: Request, res: Response) => {
    const { name, lastName, email, password } = req.body;
    const user = await userApp.register({ name, lastName, email, password });
    req.session.userId = user.id;
    req.session.save();
    return res.status(201).json(user);
  }
);

app.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const { isPasswordValid, userId } = await userApp.login({ email, password });
  if (isPasswordValid) {
    req.session.userId = userId;
    req.session.save();
  }
  return res.sendStatus(200);
});

app.get('/secret', (req: Request, res: Response) => {
  if (req.session.userId) {
    return res.send(`Logado com sucesso! Seu id: ${req.session.userId}`);
  }

  return res.send('Nao esta logado');
});

connect();

app.listen(3000);
