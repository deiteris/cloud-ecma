require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const NodeCache = require('node-cache')
const crypto = require('crypto')

const PORT = process.env.PORT || 5000
const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const JWT_SECRET = process.env.JWT_SECRET
const TOKEN_TTL = 3600

const token_storage = new NodeCache({
  stdTTL: TOKEN_TTL,
  checkperiod: 30,
  useClones: false
})
const code_storage = new NodeCache({
  stdTTL: 300,
  checkperiod: 5,
  useClones: false
})

const app = express()
app.disable('x-powered-by')

const auth = function(req, res, next) {
  const authorization = req.headers.authorization
  if (!authorization || !authorization.startsWith('Bearer ')) {
    res.status(403).json({
      error: "This endpoint requires authentication."
    })
    return
  }
  const access_token = authorization.slice('Bearer '.length)
  const client_data = token_storage.get(access_token)
  if (!client_data) {
    res.status(403).json({
      error: "Access token is either expired or doesn't exist."
    })
    return
  }
  req.client_data = client_data
  next()
}

app.get('/api/v2/tenants', auth, (req, res) => {
  const scope = req.client_data.scope
  if (!scope || !scope.split(' ').includes('list_tenants')) {
    res.status(403).json({
      error: "The 'list_tenants' scope is required to access this endpoint."
    })
    return
  }
  
  res.json(
    {
      "items": [
        {
          "id": "f313ecf6-9256-4afd-9d47-72e032ee81d0",
          "name": "The Qwerty Tenant",
          "enabled": true
        },
        {
          "id": "1e4d7438-0ebe-11e7-b131-c7b5bde6feed",
          "name": "The FooBar Tenant",
          "enabled": false
        },
        {
          "id": "5d92a310-0ee7-11e7-95e6-5f64824358de",
          "name": "The Another Tenant",
          "enabled": true
        }
      ]
    }
  )
})

app.get('/api/v2/idp/authorize', express.urlencoded({extended: true}), (req, res) => {
  console.log(req.query)
  const response_type = req.query.response_type
  if (!response_type || response_type !== 'code') {
    res.status(400).json({
      error: "The 'response_type' parameter accepts only 'code'."
    })
    return
  }
  const client_id = req.query.client_id
  if (!client_id || client_id !== CLIENT_ID) {
    res.status(400).json({
      error: "Specified client ID is not registered."
    })
    return
  }
  const redirect_uri = req.query.redirect_uri
  if (!redirect_uri || redirect_uri !== 'https://ecma-app.com/app/callback') {
    res.status(400).json({
      error: "Specified 'redirect_uri' is invalid."
    })
    return
  }
  const scope = req.query.scope
  if (!scope || !scope.split(' ').includes('openid')) {
    res.status(400).json({
      error: "Scopes must include at least 'openid' scope."
    })
    return
  }

  const code = crypto.randomBytes(8).toString('hex')
  code_storage.set(code, {client_id, scope, redirect_uri})
  res.redirect(302, `${redirect_uri}?code=${code}`)
})

app.post('/api/v2/idp/token', express.urlencoded({extended: true}), (req, res) => {
  console.log(req.query)

  const grant_type = req.query.grant_type
  let recv_scope = req.query.scope

  if (!['client_credentials', 'authorization_code'].includes(grant_type)) {
    res.status(400).json(({
      error: "Unsupported grant type."
    }))
    return
  }

  let credentials = req.headers.authorization
  if (!credentials) {
    res.status(400).json({
      error: 'No client credentials specified.'
    })
    return
  }
  if (!credentials.startsWith('Basic ')) {
    res.status(400).json({
      error: 'Client credentials must be provided using Basic Authorization.'
    })
    return
  }

  credentials = credentials.slice("Basic ".length)

  const [recv_client_id, recv_client_secret] = Buffer.from(credentials, 'base64').toString('utf-8').split(':')

  if (recv_client_id !== CLIENT_ID || recv_client_secret !== CLIENT_SECRET) {
    res.status(401).json({
      error: 'Unauthorized client.'
    })
    return
  }

  if (grant_type === 'authorization_code') {
    const code_data = code_storage.get(req.query.code)
    if (!code_data) {
      res.status(401).json({
        error: "Invalid code provided."
      })
      return
    }
    const {client_id, scope, redirect_uri} = code_data
    if (client_id !== recv_client_id) {
      res.status(401).json({
        error: "Client ID doesn't match the client ID that was used to issue this code."
      })
      return
    }
    const recv_redirect_uri = req.query.redirect_uri
    if (redirect_uri !== recv_redirect_uri) {
      res.status(401).json({
        error: "Redirect URI doesn't match the redirect URI that was used to issue this code."
      })
      return
    }
    recv_scope = scope
    code_storage.del(req.query.code)
  }

  const token_data = {
    client_id: recv_client_id, 
    client_secret: recv_client_secret, 
    scope: recv_scope
  }
  const id_token = jwt.sign(token_data, JWT_SECRET, {
    issuer: 'https://cloud-ecma.herokuapp.com/',
    expiresIn: TOKEN_TTL
  })
  const access_token = crypto.randomBytes(32).toString('hex')

  token_storage.set(access_token, {id_token, scope: recv_scope})
  res.json(
    {
      access_token,
      expires_in: TOKEN_TTL,
      token_type: "Bearer",
      id_token,
    }
  )
})

app.get('/.well_known/oauth-authorization-server', (_, res) => {
  res.json(
    {
      "authorization_endpoint": "https://cloud-ecma.herokuapp.com/api/v2/idp/authorize",  // GET method always responds with code 302
      "jwks_uri": "https://cloud-ecma.herokuapp.com/api/v2/idp/keys",
      "response_types_supported": [
        "code"
      ],
      "token_endpoint_auth_methods_supported": ["client_secret_basic"],
      "token_endpoint": "https://cloud-ecma.herokuapp.com/api/v2/idp/token",  // POST method, successful response code is 200
      "token_endpoint_auth_signing_alg_values_supported": [
        "HS256"
      ],
      "issuer": "https://cloud-ecma.herokuapp.com/"
    }    
  )
})

app.get('/.well_known/openid-configuration', (_, res) => {
  res.json(
    {
      "authorization_endpoint": "https://cloud-ecma.herokuapp.com/api/v2/idp/authorize",  // GET method always responds with code 302
      "subject_types_supported": [
        "public",
        "pairwise"
      ],
      "jwks_uri": "https://cloud-ecma.herokuapp.com/api/v2/idp/keys",
      "response_types_supported": [
        "code"
      ],
      "token_endpoint": "https://cloud-ecma.herokuapp.com/api/v2/idp/token",  // POST method, successful response code is 200
      "id_token_signing_alg_values_supported": [
        "HS256"
      ],
      "issuer": "https://cloud-ecma.herokuapp.com/"
    }
  )
})

app.get('/', (_, res) => {
  res.send('Hey there :)')
})

app.listen(PORT, () => console.log(`Listening on ${ PORT }`))