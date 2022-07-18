import jwt from 'jsonwebtoken';

export class Authorizer {

  #jwtPublicKey;
  #jwtPrivateKey;
  #staticSecrets;

  #tokens = new Set();

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

  encrypt({
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
    const token = jwt.sign({
      ...data
    }, this.#jwtPrivateKey, {
      expiresIn,
      algorithm: 'RS256'
    });
    this.#tokens.add(token);
    return token;
  }

  decrypt(tokenOrReq) {
    if (!this.#jwtPublicKey || !this.#jwtPrivateKey) {
      throw new Error('"init" must be called with JWT public and private keys first.');
    }
    const token = this.#parseToken(tokenOrReq);
    if (!this.#tokens.has(token)) {
      throw new Error('"token" is invalid.');
    }
    const decrypted = jwt.verify(token, this.#jwtPublicKey);
    return decrypted;
  }

  #parseToken(tokenOrReq) {
    if (tokenOrReq && !tokenOrReq.headers) return tokenOrReq;
    const header = tokenOrReq?.headers?.authorization?.split(' ') || [];
    const token = header[0] == 'Bearer' && header[1];
    return token;
  }

  isValid(tokenOrReq) {
    try {
      this.decrypt(tokenOrReq);
      return true;
    } catch(error) {
      return false;
    }
  }

  invalidateToken(tokenOrReq) {
    const token = this.#parseToken(tokenOrReq);
    this.#tokens.delete(token);
  }

  resetToken(tokenOrReq) {
    const token = this.#parseToken(tokenOrReq);
    const decrypted = this.decrypt(token);
    if (!decrypted.origIat) decrypted.origIat = decrypted.iat;
    const expiresIn = decrypted.exp - decrypted.iat;
    delete decrypted.exp;
    delete decrypted.iat;
    this.invalidateToken(token);
    return this.encrypt({
      expiresIn,
      data: decrypted
    });
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
      const isValid = this.isValid(req);
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
