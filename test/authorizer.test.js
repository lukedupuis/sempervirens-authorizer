import chai from 'chai';
import spies from 'chai-spies';
import { readFileSync } from 'fs';
import jwt from 'jsonwebtoken';

import authorizer from '../src/authorizer.class.js';

chai.use(spies);
const { expect, spy } = chai;

const jwtPublicKey = readFileSync('./security/jwt/jwtRS256.key.pub', 'utf8');
const jwtPrivateKey = readFileSync('./security/jwt/jwtRS256.key', 'utf8');

describe('1. authorizer', () => {

  describe('1.1. When functions relying on the JWT public and private keys are called before passing the keys into "init"', () => {
    // return;

    describe('1.1.1. When "ecrypt" is called', () => {
      // return;
      it('1.1.1.1. Should throw an error', () => {
        try {
          authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
          expect(false).to.be.true;
        } catch(error) {
          expect(error.message).to.equal('"init" must be called with JWT public and private keys first.');
        }
      });
    });

    describe('1.1.2. When "decrypt" is called', () => {
      // return;
      it('1.1.2.1. Should throw an error', () => {
        try {
          authorizer.decrypt('token');
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
      // return;

      describe('1.2.1.1. When "jwtPublicKey" is not given', () => {
        // return;
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
        // return;
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

  describe('1.3. When "encrypt" is called', () => {
    // return;

    describe('1.3.1. When required properties are not given', () => {
      // return;

      describe('1.3.1.1. When "expiresIn" is not given', () => {
        // return;
        it('1.3.1.1.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          try {
            authorizer.encrypt({ data: { test: 1 } });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"expiresIn" is required.');
          }
        });
      });

      describe('1.3.1.2. When "data" is not given or is an empty object', () => {
        // return;
        it('1.3.1.2.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          try {
            authorizer.encrypt({ expiresIn: '1m' });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"data" is required and must be a key:value object.');
          }
          try {
            authorizer.encrypt({ expiresIn: '1m', data: {} });
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"data" is required and must be a key:value object.');
          }
        });
      });

    });

    describe('1.3.2. When the token is created successfully', () => {
      // return;
      it('1.3.2.1. Should return a token containing certain properties', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const decrypted = jwt.verify(token, jwtPublicKey);
        expect(decrypted.test).to.equal(1);
        expect(typeof decrypted.iat == 'number').to.be.true;
        expect(typeof decrypted.exp == 'number').to.be.true;
      });
    });

  });

  // return;

  describe('1.4. When "decrypt" is called', () => {
    // return;

    describe('1.4.1. When required properties are not given', () => {
      // return;

      describe('1.4.1.1. When "token" is not valid', () => {
        // return;
        it('1.4.1.1.1. Should throw an error', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          try {
            authorizer.decrypt();
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"token" is invalid.');
          }
          // return;
          try {
            authorizer.decrypt(1);
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"token" is invalid.');
          }
          // return;
          try {
            authorizer.decrypt('not a valid token');
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('"token" is invalid.');
          }
        });
      });

      describe('1.4.1.2. When "token" has expired', () => {
        // return;
        it('1.4.1.2.1. Should throw an error', async () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          const token = authorizer.encrypt({ expiresIn: '1s', data: { test: 1 } });
          await new Promise(resolve => setTimeout(resolve, 1200));
          try {
            authorizer.decrypt(token);
            expect(false).to.be.true;
          } catch(error) {
            expect(error.message).to.equal('jwt expired');
          }
        });
      });

    });

    // return;

    describe('1.4.2. When a valid token is given', () => {
      // return;

      describe('1.4.2.1. When the token is given directly', () => {
        // return;
        it('1.4.2.1.1. Should decrypt the token', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
          const decrypted = authorizer.decrypt(token);
          expect(decrypted.iat).to.exist;
          expect(decrypted.exp).to.exist;
          expect(decrypted.test).to.equal(1);
        });
      });

      describe('1.4.2.1. When the token is given as a request object with an authorization header', () => {
        // return;
        it('1.4.2.1.1. Should decrypt the token', () => {
          authorizer.init({ jwtPublicKey, jwtPrivateKey });
          const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
          const req = { headers: { authorization: `Bearer ${token}` } };
          const decrypted = authorizer.decrypt(req);
          expect(decrypted.iat).to.exist;
          expect(decrypted.exp).to.exist;
          expect(decrypted.test).to.equal(1);
        });
      });
    });

  });

  // return;

  describe('1.7. When "isValid" is called', () => {
    // return;

    describe('1.7.1. When token is valid', () => {
      // return;
      it('1.7.1.1. Should return true', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const isValid = authorizer.isValid(token);
        expect(isValid).to.be.true;
      });
    });

    describe('1.7.2. When token is not valid', () => {
      // return;
      it('1.7.2.1. Should return false', async () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '.5s', data: { test: 1 } });
        await new Promise(resolve => setTimeout(resolve, 600));
        const isValid = authorizer.isValid(token);
        expect(isValid).to.be.false;
      });
    });

  });

  // return;

  describe('1.8. When "invalidate" is called', () => {
    // return;

    describe('1.8.1. When the token is given directly', () => {
      // return;
      it('1.8.1.1. Should invalitate the token', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const isValid1 = authorizer.isValid(token);
        expect(isValid1).to.be.true;
        authorizer.invalidate(token);
        const isValid2 = authorizer.isValid(token);
        expect(isValid2).to.be.false;
      });
    });

    describe('1.8.2. When the token is given as a request object with an authorization header', () => {
      // return;
      it('1.8.2.1. Should invalitate the token', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const req = { headers: { authorization: `Bearer ${token}` } };
        const isValid1 = authorizer.isValid(req);
        expect(isValid1).to.be.true;
        authorizer.invalidate(req);
        const isValid2 = authorizer.isValid(token);
        expect(isValid2).to.be.false;
      });
    });

  });

  // return;

  describe('1.9. When "reset" is called', () => {

    describe('1.9.1. When the token is given directly', () => {
      // return;
      it('1.9.1.1. Should reset the token', async () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token1 = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const decrypted1 = authorizer.decrypt(token1);
        expect(decrypted1.origIat).to.be.undefined;
        await new Promise(resolve => setTimeout(() => resolve(), 1000));
        const token2 = authorizer.reset(token1);
        const decrypted2 = authorizer.decrypt(token2);
        expect(decrypted2.origIat).to.equal(decrypted1.iat);
        expect(decrypted2.iat).to.be.greaterThan(decrypted1.iat);
        expect(decrypted2.exp).to.be.greaterThan(decrypted1.exp);
      });
    });

    describe('1.9.2. When the token is given as a request object with an authorization header', () => {
      // return;
      it('1.9.2.1. Should reset the token', async () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token1 = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const decrypted1 = authorizer.decrypt(token1);
        expect(decrypted1.origIat).to.be.undefined;
        await new Promise(resolve => setTimeout(() => resolve(), 1000));
        const req = { headers: { authorization: `Bearer ${token1}` } };
        const token2 = authorizer.reset(req);
        const decrypted2 = authorizer.decrypt(token2);
        expect(decrypted2.origIat).to.equal(decrypted1.iat);
        expect(decrypted2.iat).to.be.greaterThan(decrypted1.iat);
        expect(decrypted2.exp).to.be.greaterThan(decrypted1.exp);
      });
    });

  });

  // return;

  describe('1.10. When "isAuthorized" is called', () => {
    // return;

    describe('1.10.1. When a valid static secret is passed as a query parameter', () => {
      // return;
      it('1.10.1.1. Should return true', () => {
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

    describe('1.10.2. When an invalid static secret is passed as a query parameter', () => {
      // return;
      it('1.10.2.1. Should return false', () => {
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

    describe('1.10.3. When a valid token is passed in the authorization header as Bearer', () => {
      // return;
      it('1.10.3.1. Should return true', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const req = { headers: { authorization: `Bearer ${token}` } };
        const isAuthorized = authorizer.isAuthorized(req);
        expect(isAuthorized).to.be.true;
      });
    });

    describe('1.10.4. When an invalid token is passed in the authorization header as Bearer', () => {
      // return;
      it('1.10.4.1. Should return true', () => {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const req = { headers: { authorization: 'Bearer token' } };
        const isAuthorized = authorizer.isAuthorized(req);
        expect(isAuthorized).to.be.false;
      });
    });

  });

  // return;

  describe('1.11. When "authorize" is called', () => {
    // return;

    describe('1.11.1. When the request is authorized', () => {
      // return;
      it('1.11.1.1. Should allow proceeding to the next middleware', () =>  {
        authorizer.init({ jwtPublicKey, jwtPrivateKey });
        const token = authorizer.encrypt({ expiresIn: '1m', data: { test: 1 } });
        const req = { headers: { authorization: `Bearer ${token}` } };
        const res = {};
        const next = spy.on(() => null);
        authorizer.authorize(req, res, next);
        expect(next).to.be.have.been.called();
      });
    });

    describe('1.11.2. When the request is not authorized', () => {
      // return;
      it('1.11.2.1. Should call prevent proceeding to the next middleware and call "sendUnauthorized"', () =>  {
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

  describe('1.12. When "sendUnauthorized" is called', () => {
    // return;
    it('1.12.1. Should call send a response with 401 status and error data ', () => {
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

  after(() => setTimeout(() => process.exit(), 500));

});
