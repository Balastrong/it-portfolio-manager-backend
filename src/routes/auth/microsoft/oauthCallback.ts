import {OauthCallbackQueryParamType} from '@src/core/Auth/model/google.auth.model'
import {FastifyInstance} from 'fastify'
import {OAuth2Client} from 'google-auth-library'
import {ConfidentialClientApplication} from "@azure/msal-node";
import {AuthorizationCodeQueryParamType} from "@src/core/Auth/model/microsoft.auth.model";

export default async function (fastify: FastifyInstance): Promise<void> {
    fastify.get<{
        Querystring: AuthorizationCodeQueryParamType
    }>(
        '/oauthCallback',
        {
            schema: {
                tags: ['Auth'],
                security: [
                    {
                        apiKey: [],
                    },
                ],
                response: {
                    401: {
                        type: 'null',
                        description: 'Unauthorized',
                    },
                    500: {
                        type: 'null',
                        description: 'Internal server error',
                    },
                },
            },
        },
        async (request, reply) => {
            const query = request.query
            if (query.error) {
                console.error(query.error)
                return reply.redirect(request.session.referer)
            }
            if (request.session.state !== query.state) {
                throw new Error('invalid state')
            }
            const oauthClient = fastify
                .dependencyInjectionContainer()
                .resolve('microsoftAuthClient') as ConfidentialClientApplication
            const token = await oauthClient.acquireTokenByCode(
                {
                    scopes: ['profile', 'email'],
                    redirectUri: `http://localhost:3000/dev/api/auth/microsoft/oauthCallback`,
                    code: request.query.code ?? '',
                    state: request.session.state
                })
            reply.redirect(
                `${request.session.referer}?token=${token.accessToken}`,
            )
        },
    )
}
