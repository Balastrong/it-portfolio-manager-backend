import {FastifyInstance} from 'fastify'
import {randomBytes} from 'crypto'

export default async function (fastify: FastifyInstance): Promise<void> {
    fastify.get(
        '/',
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
            const state = randomBytes(32).toString('hex')
            request.session.state = state
            request.session.referer = request.headers.referer ?? ''
            // const tenant = 'common'; // common, organizations, consumers pt.clara.net, f87a7640-3b94-4bbd-b5fa-b4c15947cf56
            const clientId = 'S8a16tq1dnnqsUPr5q8x7zRUHgQgDVpT';
            const redirectUri = `http://localhost:3000/dev/api/auth/microsoft/oauthCallback`
            // const redirectUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize?` +
            //     `client_id=${clientId}` +
            //     '&response_type=code' +
            //     `&redirect_uri=${redirectUri}` +
            //     '&response_mode=query' +
            //     '&scope=https%3A%2F%2Fgraph.microsoft.com%2Fmail.read' +
            //     `&state=${state}`
            //     '&code_challenge=YTFjNjI1OWYzMzA3MTI4ZDY2Njg5M2RkNmVjNDE5YmEyZGRhOGYyM2IzNjdmZWFhMTQ1ODg3NDcxY2Nl' +
            //     '&code_challenge_method=S256'

            const redirectUrl = await fastify
                .dependencyInjectionContainer()
                .resolve('microsoftAuthClient')
                .getAuthCodeUrl({
                    clientId,
                    responseType: 'code',
                    redirectUri,
                    responseMode: 'query',
                    scopes: ['profile', 'email'],
                    state
                })
            reply.redirect(redirectUrl)
        },
    )
}