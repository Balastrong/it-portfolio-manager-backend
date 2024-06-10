import { ProviderInterface } from './providerInterface'
import { UnauthorizedError } from '@src/core/customExceptions/UnauthorizedError'
import { AuthInfoType } from '../model/Auth.model'
import {CryptoProvider} from "@azure/msal-node";
import {JWT, JwtHeader, TokenOrHeader} from "@fastify/jwt";
import buildGetJwks from "get-jwks";

export class MicrosoftProvider implements ProviderInterface {
  constructor(private jwt: JWT) {}

  async getAuthInfo(token: string): Promise<AuthInfoType> {
    const decodedToken = this.jwt.decode<TokenOrHeader>(token, {
      complete: true,
    })
    if (!decodedToken) {
      throw new UnauthorizedError()
    }
    const getJwks = buildGetJwks()
    const jwtHeader: JwtHeader =
        'header' in decodedToken ? decodedToken.header : decodedToken
    const { kid, alg } = jwtHeader
    const iss = 'payload' in decodedToken ? decodedToken?.payload?.iss : ''
    const key = await getJwks.getPublicKey({ kid, alg, domain: iss })
    const { email, name, picture } = this.jwt.verify<{
      email: string
      name: string
      picture: string
    }>(token, { key: key })
    if (!email || !name || !picture) {
      throw new UnauthorizedError()
    }
    if (email.includes('it.clara.net')) {
      email.replace('it.clara.net', 'claranet.com')
    }
    return {
      email: email.toLowerCase(),
      name,
      picture,
      companyDomain: 'it.clara.net',
    }
  }
}
