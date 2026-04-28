import { WorkOS } from '@workos-inc/node';
import {
  authCookieOptions,
  getEnv,
  logHandler,
  markResolvers,
  redis,
  updateSaasOrganization,
} from 'erxes-api-shared/utils';
import * as jwt from 'jsonwebtoken';
import { IContext } from '~/connectionResolvers';
import {
  getCallbackRedirectUrl,
  isValidEmail,
  sendSaasMagicLinkEmail,
} from '~/modules/auth/utils';
import { assertSaasEnvironment } from '~/utils/saas';

type LoginParams = {
  email: string;
  password: string;
  deviceToken?: string;
};

export const authMutations = {
  /*
   * Login   */
  async login(
    _parent: undefined,
    args: LoginParams,
    { req, res, requestInfo, models, subdomain }: IContext,
  ) {
    return await logHandler(
      async () => {
        const response = await models.Users.login(args);

        const { token } = response;

        const sameSite = getEnv({ name: 'SAME_SITE' });
        const DOMAIN = getEnv({ name: 'DOMAIN', subdomain });

        const cookieOptions: any = { secure: requestInfo.secure };
        if (
          sameSite &&
          sameSite === 'none' &&
          res.req.headers.origin !== DOMAIN
        ) {
          cookieOptions.sameSite = sameSite;
        }

        res.cookie('auth-token', token, authCookieOptions(cookieOptions));

        return 'loggedIn';
      },
      {
        subdomain,
        source: 'auth',
        action: 'login',
        userId: (await models.Users.findOne({ email: args.email }).lean())?._id,
        payload: {
          headers: req.headers,
          email: args?.email,
          method: 'email/password',
        },
      },
      null,
      null,
      true,
    );
  },
  /*
   * logout
   */
  async logout(
    _parent: undefined,
    _args: undefined,
    { req, res, user, requestInfo, models, subdomain }: IContext,
  ) {
    await logHandler(
      async () => {
        const logout = await models.Users.logout(
          user,
          requestInfo.cookies['auth-token'],
        );
        res.clearCookie('auth-token');
        return logout;
      },
      {
        subdomain,
        source: 'auth',
        action: 'logout',
        userId: user._id,
        payload: { headers: req.headers, email: user?.email },
      },
    );
  },

  /*
   * Send forgot password email
   *
   * The response intentionally does not vary based on whether the supplied
   * email is registered. Disclosing that distinction (via either an error
   * message or a divergent return value) would allow an unauthenticated
   * attacker to enumerate user accounts (OWASP A07:2021). All errors raised
   * during lookup or email delivery are swallowed for the same reason; the
   * caller always sees the same generic acknowledgement.
   */
  async forgotPassword(
    _parent: undefined,
    { email }: { email: string },
    { subdomain, models }: IContext,
  ) {
    try {
      const token = await models.Users.forgotPassword(email);

      if (token) {
        // send email ==============
        const DOMAIN = getEnv({ name: 'DOMAIN', subdomain });

        const link = `${DOMAIN}/reset-password?token=${token}`;

        // await utils.sendEmail(
        //   subdomain,
        //   {
        //     toEmails: [email],
        //     title: 'Reset password',
        //     template: {
        //       name: 'resetPassword',
        //       data: {
        //         content: link,
        //       },
        //     },
        //   },
        //   models
        // );
        void link;
      }
    } catch (_e) {
      // Suppress any underlying error (lookup, SMTP, template) so the response
      // cannot be used to distinguish registered from unregistered emails.
    }

    return 'sent';
  },

  /*
   * Reset password
   */
  async resetPassword(
    _parent: undefined,
    args: { token: string; newPassword: string },
    { models }: IContext,
  ) {
    return models.Users.resetPassword(args);
  },

  async loginWithGoogle(
    _parent: undefined,
    _params: undefined,
    { models, subdomain }: IContext,
  ) {
    assertSaasEnvironment();
    const WORKOS_API_KEY = getEnv({ name: 'WORKOS_API_KEY', subdomain });
    const CORE_DOMAIN = getEnv({ name: 'CORE_DOMAIN', subdomain });

    const workosClient = new WorkOS(WORKOS_API_KEY);

    const state = await jwt.sign(
      {
        subdomain,
        redirectUri: getCallbackRedirectUrl(subdomain, 'sso-callback'),
      },
      models.Users.getSecret(),
      { expiresIn: '1d' },
    );

    const authorizationURL = workosClient.sso.getAuthorizationUrl({
      provider: 'GoogleOAuth',
      redirectUri: `${CORE_DOMAIN}/saas-sso-callback`,

      clientId: getEnv({ name: 'WORKOS_PROJECT_ID', subdomain }),
      state,
    });

    await updateSaasOrganization(subdomain, {
      lastActiveDate: Date.now(),
    });

    return authorizationURL;
  },

  async loginWithMagicLink(
    _,
    { email }: { email: string },
    { models, subdomain }: IContext,
  ) {
    assertSaasEnvironment();

    const WORKOS_API_KEY = getEnv({ name: 'WORKOS_API_KEY', subdomain });
    const CORE_DOMAIN = getEnv({ name: 'CORE_DOMAIN', subdomain });
    const workosClient = new WorkOS(WORKOS_API_KEY);

    if (!isValidEmail(email)) {
      throw new Error(
        'Invalid email address provided. Please enter a valid email.',
      );
    }

    const user = await models.Users.findOne({
      email,
    });

    if (!user) {
      return 'Invalid login';
    }

    const token = await jwt.sign(
      {
        user: await models.Users.getTokenFields(user),
        subdomain,
        redirectUri: getCallbackRedirectUrl(subdomain, 'ml-callback'),
      },
      models.Users.getSecret(),
      { expiresIn: '1d' },
    );

    // validated tokens are checked at user middleware
    await models.Users.updateOne(
      { _id: user._id },
      { $push: { validatedTokens: token } },
    );

    // will use subdomain when workos callback data arrives
    await redis.set('subdomain', subdomain);

    const session = await workosClient.passwordless.createSession({
      email,
      type: 'MagicLink',
      state: token,
      redirectURI: `${CORE_DOMAIN}/saas-ml-callback`,
    });

    await sendSaasMagicLinkEmail({
      subdomain,
      models,
      toEmail: email,
      link: session.link,
    });

    await updateSaasOrganization(subdomain, {
      lastActiveDate: Date.now(),
    });

    return 'success';
  },
};

markResolvers(authMutations, {
  wrapperConfig: {
    skipPermission: true,
  },
});
