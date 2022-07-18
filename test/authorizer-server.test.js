import http from 'http';
import { readFileSync } from 'fs';
import express from 'express';
import superagent from 'superagent';
import { expect } from 'chai';
import authorizer from '../src/authorizer.class.js';

const jwtPublicKey = readFileSync('./security/jwt/jwtRS256.key.pub', 'utf8');
const jwtPrivateKey = readFileSync('./security/jwt/jwtRS256.key', 'utf8');

authorizer.init({ jwtPublicKey, jwtPrivateKey });

const app = express();
app.use(express.json());

// Set up a /login route
app.post('/login', (req, res, next) => {
  const { email, password } = req.body;
  // Validate email/password combination; do not use the following except for testing
  const isValid = email == 'test@test.com' && password == 'testpassword';
  if (isValid) {
    const token = authorizer.encrypt({
      expiresIn: '10m',
      data: { email }
    });
    res.json({ token });
  } else {
    res.json({ error: 'Invalid credentials' });
  }
});

// Set up a protected resource route
app.get('/profile/:id', (req, res, next) => {
  const { id } = req.params;
  if (authorizer.isAuthorized(req)) { // Pass request header 'Authorization': 'Bearer ${token}'
    const profile = {
      id,
      email: 'test@test.com',
      name: 'FirstTest LastTest'
    };
    res.json({ profile });
  } else {
    authorizer.sendUnauthorized(res); // Or send a custom response
  }
});

http.createServer(app).listen(8080);

describe('2. When authorizer is used in Express routes', () => {
  // return;

  describe('2.1. When an endpoint implements "encrypt"', () => {
    // return;
    it('2.1.1. Should return a token', async () => {
      const { body: b1 } = await superagent
        .post('http://localhost:8080/login')
        .send({
          email: 'test@test.com',
          password: 'testpassword'
        });
      expect(b1.token).to.exist;
    });
  });

  describe('2.2. When an endpoint implements "isAuthorized"', () => {
    // return;

    describe('2.2.1. When the request is authorized', () => {
      // return;
      it('2.2.1.1. Should return the requested data', async () => {
        const { body: b1 } = await superagent
          .post('http://localhost:8080/login')
          .send({
            email: 'test@test.com',
            password: 'testpassword'
          });
        const { body: b2 } = await superagent
          .get('http://localhost:8080/profile/test-id')
          .set('Authorization', `Bearer ${b1.token}`)
          .send();
        expect(b2.profile.email).to.equal('test@test.com');
      });
    });

    describe('2.2.2. When the request is not authorized', () => {
      // return;
      it('2.2.2.1. Should return an error', async () => {
        try {
          await superagent
            .get('http://localhost:8080/profile/test-id')
            .set('Authorization', `Bearer token`)
            .send();
        } catch(error) {
          expect(error.message).to.equal('Unauthorized');
          expect(error.response.body.error.code).to.equal('UNAUTHORIZED_ERROR');
        }

      });
    });

  });

  after(() => setTimeout(process.exit, 100));

});