# Sempervirens Authorizer
Middleware for authorizing requests to an Express server.

## Installation

`npm i @sempervirens/authorizer`

## Usage

### Overview

1. Create JWT private and public keys.

```
mkdir security && cd security && mkdir jwt && cd jwt
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
```

2. Import `authorizer` into the server's main file, and then initialize `authorizer` with the JWT public and private keys.

3. Set up a route that uses `authorizer.encryptJwt` to create a token and return the token to the client.

4. Set up another route with a protected resource that requires a valid token.

5. From the client, send a request to the server to get the token.

6. From the client, send a second request for the protected resource, including the `'Authorization': 'Bearer ${token}'` header.

### Example

```
import { readFileSync } from 'fs';
import express from 'express';
import authorizer from '@sempervirens/authorizer';

const jwtPublicKey = readFileSync('./security/jwt/jwtRS256.key.pub', 'utf8');
const jwtPrivateKey = readFileSync('./security/jwt/jwtRS256.key', 'utf8');

authorizer.init({
  jwtPublicKey,
  jwtPrivateKey
});

const app = express();
app.use(express.json());

// Set up a /login route
app.post('/login', async (req, res, next) => {
  const { email, password } = req.body;
  // Validate email/password combination; do not use the following except for testing
  const isValid = email == 'test@test.com' && password == 'testpassword';
  if (isValid) {
    const token = authorizer.encryptJwt({
      expiresIn: '10m',
      data: { email }
    });
    res.json({ token });
  } else {
    res.json({ error: 'Invalid credentials' });
  }
});

// Set up a protected resource route
app.get('/profile/:id', async (req, res, next) => {
  if (authorizer.isAuthorized(req)) { // Pass request header 'Authorization': 'Bearer ${token}'
    const profile = {
      email: 'test@test.com',
      name: 'FirstTest LastTest'
    };
    res.json({ profile });
  } else {
    authorizer.sendUnauthorized(res); // Or send a custom response
  }
});

```

## API

### authorizer (Singleton instance)

| Prop  | Type | Params | Description |
|-------|------|--------|-------------|
| `init` | Function | `{ jwtPublicKey = '', jwtPrivateKey = '' }` | Initializes the instance properties. |
| `encryptJwt` | Function | `{ expiresIn = '', data: {} }` | Returns a JWT token. |
| `decryptJwt` | Function | `token` | Decrypts a JWT token. |
| `getHeaderToken` | Function | `req: express.Request` | Parses a token from the `'Authorization': 'Bearer ${token}'` header, returning the token. |
| `decryptHeaderToken` | Function | `req: express.Request` | Parses a token from the `'Authorization': 'Bearer ${token}'` header, decrypts it, and returns the decrypted data. |
| `isTokenValid` | Function | `token` | Returns `true` or `false`. |
| `isAuthorized` | Function | `req: express.Request` | Parses a token from the `'Authorization': 'Bearer ${token}'`, checks if it's valid, and returns `true` or `false` |
| `authorize` | Function | `req: express.Request, res: express.Request, next` | Checks if the token is valid. If so, it calls next. If not, it calls `sendUnauthorized`.|
| `sendUnauthorized` | Function | `res: express.Request` | Sends a 401 response with a pre-formatted data object in the same shape as `@sempervirens/endpoint`'s error response.|