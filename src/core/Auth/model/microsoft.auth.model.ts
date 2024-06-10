import { Static, Type } from '@sinclair/typebox'

export const AuthorizationCodeQueryParam = Type.Object({
  error: Type.Optional(Type.String()),
  code: Type.Optional(Type.String()),
  state: Type.Optional(Type.String()),
})

export type AuthorizationCodeQueryParamType = Static<typeof AuthorizationCodeQueryParam>
