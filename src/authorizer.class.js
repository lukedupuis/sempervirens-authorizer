import jwt from 'jsonwebtoken';

export class Authorizer {

  #jwtPublicKey;
  #jwtPrivateKey;
  #staticSecrets;

  constructor() {}

  init({
    jwtPublicKey,
    jwtPrivateKey,
    staticSecrets
  }) {
    if (!jwtPublicKey) throw new Error('"jwtPublicKey" is required.');
    if (!jwtPrivateKey) throw new Error('"jwtPrivateKey" is required.');
    this.#jwtPublicKey = jwtPublicKey;
    this.#jwtPrivateKey = jwtPrivateKey;
    this.#staticSecrets = staticSecrets || {};
  }

  // Tokens

  encryptJwt({
    expiresIn,
    data = {}
  }) {
    if (!this.#jwtPublicKey || !this.#jwtPrivateKey) {
      throw new Error('"init" must be called with JWT public and private keys first.');
    }
    if (!expiresIn) {
      throw new Error('"expiresIn" is required.');
    }
    if (!data || typeof data != 'object' || Object.keys(data).length == 0) {
      throw new Error('"data" is required and must be a key:value object.');
    }
    return jwt.sign({
      ...data,
      expiresIn
    }, this.#jwtPrivateKey, {
      expiresIn,
      algorithm: 'RS256'
    });
  }

  decryptJwt(token) {
    if (!this.#jwtPublicKey || !this.#jwtPrivateKey) {
      throw new Error('"init" must be called with JWT public and private keys first.');
    }
    if (!token || typeof token != 'string') {
      throw new Error('"token" is required and must be a string.');
    }
    const decrypted = jwt.verify(token, this.#jwtPublicKey);
    decrypted.createdAt = new Date(decrypted.iat * 1000);
    decrypted.expiresAt = new Date(decrypted.exp * 1000);
    return decrypted;
  }

  getHeaderToken(req) {
    const header = req?.headers?.authorization?.split(' ') || [];
    const token = header[0] == 'Bearer' && header[1];
    return token;
  }

  decryptHeaderToken(req) {
    const token = this.getHeaderToken(req);
    const decrypted = this.decryptJwt(token);
    return decrypted;
  }

  isTokenValid(token) {
    try {
      this.decryptJwt(token);
      return true;
    } catch(error) {
      return false;
    }
  }

  // Authorization

  #isValidStaticSecret(req) {
    const { query } = req;
    for (const k in query) {
      const staticSecret = this.#staticSecrets[k];
      if (staticSecret && staticSecret == query[k]) {
        return true;
      }
    }
    return false;
  }

  isAuthorized(req) {
    if (this.#isValidStaticSecret(req)) {
      return true;
    } else {
      const token = this.getHeaderToken(req);
      const isValid = this.isTokenValid(token);
      return isValid;
    }
  }

  authorize(req, res, next) {
    if (this.isAuthorized(req)) {
      next();
    } else {
      this.sendUnauthorized(res);
    }
  }

  sendUnauthorized(res) {
    res.status(401).send({
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
  }

}

export default new Authorizer();
