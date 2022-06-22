import chai from 'chai';
import spies from 'chai-spies';
import { readFileSync } from 'fs';
import jwt from 'jsonwebtoken';

import authorizer from '../src/authorizer.class.js';

chai.use(spies);
const { expect, spy } = chai;

const jwtPublicKey = readFileSync('./security/jwt/jwtRS256.key.pub', 'utf8');
const jwtPrivateKey = readFileSync('./security/jwt/jwtRS256.key', 'utf8');

describe('1. Authorizer', () => {

  describe('1.1. When functions relying on the JWT public and private keys are called before passing the keys into "init"', () => {
    // return;
    describe('1.1.1. When "encryptJwt" is called', () => {
      it('1.1.1.1. Should throw an error', () => {
        try {
          authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
          expect(false).to.be.true;
        } catch(error) {
          expect(error.message).to.equal('"init" must be called with JWT public and private keys first.');
        }
      });
    });

    describe('1.1.2. When "decryptJwt" is called', () => {
      it('1.1.2.1. Should throw an error', () => {
        try {
          authorizer.decryptJwt('token');
          expect(false).to.be.true;
        } catch(error) {
          expect(error.message).to.equal('"init" must be called with JWT public and private keys first.');
        }
      });
    });

  });

  // return;

  describe('1.2. When "init" is called', () => {
    // return;
    describe('1.2.1. When required properties are not given', () => {
      describe('1.2.1.1. When "jwtPublicKey" is not given', () => {
        it('1.2.1.1.1. An error should be thrown', () => {
          try {
            authorizer.init({ jwtPrivateKey });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"jwtPublicKey" is required.');
          }
        });
      });
      describe('1.2.1.2. When "jwtPrivateKey" is not given', () => {
        it('1.2.1.2.1. An error should be thrown', () => {
          try {
            authorizer.init({ jwtPublicKey });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"jwtPrivateKey" is required.');
          }
        });
      });
    });
  });

  // return;

  describe('1.3. When "encryptJwt" is called', () => {
    return;

    describe('1.3.1. When required properties are not given', () => {

      describe('1.3.1.1. When "expiresIn" is not given', () => {
        it('1.3.1.1.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          try {
            authorizer.encryptJwt({ data: { test: 1 } });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"expiresIn" is required.');
          }
        });
      });

      describe('1.3.1.2. When "data" is not given or is an empty object', () => {
        it('1.3.1.2.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          try {
            authorizer.encryptJwt({ expiresIn: '1m' });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"data" is required and must be a key:value object.');
          }
          try {
            authorizer.encryptJwt({ expiresIn: '1m', data: {} });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"data" is required and must be a key:value object.');
          }
        });
      });

    });

    describe('1.3.2. When the token is created successfully', () => {
      it('1.3.2.1. Should return a token', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
        const decrypted = jwt.verify(token, jwtPublicKey);
        expect(decrypted.test).to.equal(1);
      });
    });

  });

  // return;

  describe('1.4. When "decryptJwt" is called', () => {
    // return;

    describe('1.4.1. When required properties are not given', () => {

      describe('1.4.1.1. When "token" is not given or is not a string', () => {
        it('1.4.1.1.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
          try {
            authorizer.decryptJwt();
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"token" is required and must be a string.');
          }
          try {
            authorizer.decryptJwt(1);
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"token" is required and must be a string.');
          }
        });
      });

      describe('1.4.1.2. When "token" is not a vaild JWT token', () => {
        it('1.4.1.2.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          try {
            authorizer.decryptJwt('not a real token');
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('jwt malformed');
          }
        });
      });

      describe('1.4.1.3. When "token" has expired', () => {
        it('1.4.1.3.1. Should throw an error', async () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          const token = authorizer.encryptJwt({ expiresIn: '.5s', data: { test: 1 } });
          await new Promise(resolve => setTimeout(resolve, 600));
          try {
            authorizer.decryptJwt(token);
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('jwt expired');
          }
        });
      });

    });

    describe('1.4.2. When a valid token is given', () => {
      it('1.4.2.1. Should decrypt the token', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
        const decrypted = authorizer.decryptJwt(token);
        expect(decrypted.iat).to.exist;
        expect(decrypted.exp).to.exist;
        expect(decrypted.createdAt).to.exist;
        expect(decrypted.expiresAt).to.exist;
        expect(decrypted.expiresIn).to.exist;
        expect(decrypted.test).to.equal(1);
      });
    });

  });

  // return;

  describe('1.5. When "getHeaderToken" is called', () => {
    // return;
    it('1.5.1. Should return the value of the Authorization Bearer', () => {
      const req = { headers: { authorization: 'Bearer token' } };
      const value = authorizer.getHeaderToken(req);
      expect(value).to.equal('token');
    });
  });

  // return;

  describe('1.6. When "decryptHeaderToken" is called', () => {
    // return;
    it('1.6.1. Should return the decrypted data', () => {
      authorizer.init({ jwtPublicKey, jwtPrivateKey });
      const token = authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
      const req = { headers: { authorization: `Bearer ${token}` } };
      const decrypted = authorizer.decryptHeaderToken(req);
      expect(decrypted.iat).to.exist;
      expect(decrypted.exp).to.exist;
      expect(decrypted.createdAt).to.exist;
      expect(decrypted.expiresAt).to.exist;
      expect(decrypted.expiresIn).to.exist;
      expect(decrypted.test).to.equal(1);
    });
  });

  // return;

  describe('1.7. When "isTokenValid" is called', () => {
    // return;

    describe('1.7.1. When token is valid', () => {
      // return;
      it('1.7.1.1. Should return true', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
        const isValid = authorizer.isTokenValid(token);
        expect(isValid).to.be.true;
      });
    });
    describe('1.7.2. When token is not valid', () => {
      // return;
      it('1.7.2.1. Should return false', async () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encryptJwt({ expiresIn: '.5s', data: { test: 1 } });
        await new Promise(resolve => setTimeout(resolve, 600));
        const isValid = authorizer.isTokenValid(token);
        expect(isValid).to.be.false;
      });
    });
  });

  // return;

  describe('1.8. When "isAuthorized" is called', () => {
    // return;

    describe('1.8.1. When a valid static secret is passed as a query parameter', () => {
      it('1.8.1.1. Should return true', () => {
        authorizer.init({
          jwtPublicKey,
          jwtPrivateKey,
          staticSecrets: { key: 'secret'}
        });
        const req = { query: { key: 'secret' } };
        const isAuthorized = authorizer.isAuthorized(req);
        expect(isAuthorized).to.be.true;
      });
    });

    describe('1.8.2. When an invalid static secret is passed as a query parameter', () => {
      it('1.8.2.1. Should return false', () => {
        authorizer.init({
          jwtPublicKey,
          jwtPrivateKey,
          staticSecrets: { key: 'secret'}
        });
        const req = { query: { key: 'secret1' } };
        const isAuthorized = authorizer.isAuthorized(req);
        expect(isAuthorized).to.be.false;
      });
    });

    describe('1.8.3. When a valid token is passed in the authorization header as Bearer', () => {
      it('1.8.3.1. Should return true', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
        const req = { headers: { authorization: `Bearer ${token}` } };
        const isAuthorized = authorizer.isAuthorized(req);
        expect(isAuthorized).to.be.true;
      });
    });

    describe('1.8.4. When an invalid token is passed in the authorization header as Bearer', () => {
      it('1.8.4.1. Should return true', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const req = { headers: { authorization: 'Bearer token' } };
        const isAuthorized = authorizer.isAuthorized(req);
        expect(isAuthorized).to.be.false;
      });
    });

  });

  // return;

  describe('1.9. When "authorize" is called', () => {
    // return;
    describe('1.9.1. When the request is authorized', () => {
      it('1.9.1.1. Should allow proceeding to the next middleware', () =>  {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encryptJwt({ expiresIn: '1m', data: { test: 1 } });
        const req = { headers: { authorization: `Bearer ${token}` } };
        const res = {};
        const next = spy.on(() => null);
        authorizer.authorize(req, res, next);
        expect(next).to.be.have.been.called();
      });
    });
    describe('1.9.2. When the request is not authorized', () => {
      it('1.9.2.1. Should call prevent proceeding to the next middleware and call "sendUnauthorized"', () =>  {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const req = { headers: { authorization: 'Bearer token' } };
        const res = { status: () => ({ send: () => null }) };
        const next = () => null;
        const sendUnauthorized = spy.on(authorizer, 'sendUnauthorized');
        authorizer.authorize(req, res, next);
        expect(sendUnauthorized).to.have.been.called();
        spy.restore(authorizer);
      });
    });
  });

  // return;

  describe('1.10. When "sendUnauthorized" is called', () => {
    it('1.10.1. Should call send a response with 401 status and error data ', () => {
      authorizer.init({ jwtPublicKey, jwtPrivateKey });let sendData;
      const send = d => sendData = d;
      const res = { status: () => ({ send }) };
      const status = spy.on(res, 'status');
      authorizer.sendUnauthorized(res);
      expect(status).to.have.been.called.with(401);
      expect(sendData).to.deep.equal({
        message: null,
        data: null,
        error: {
          number: 402941,
          code: 'UNAUTHORIZED_ERROR',
          message: 'Unauthorized',
          stack: null,
          data: null
        }
      });
    });
  });

});
