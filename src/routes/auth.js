function registerAuthRoutes(app, {
  store,
  config,
  bcrypt,
  speakeasy,
  QRCode,
  asyncHandler,
  setFlash,
  clearSetupSecret,
  regenerateSession,
  saveSession,
  sessionCookieName,
  sessionCookieOptions
}) {
  app.get(
    '/setup',
    asyncHandler(async (req, res) => {
      if (store.hasUsers()) {
        res.redirect('/login');
        return;
      }

      if (!req.session.setupTotpSecret || !req.session.setupTotpOtpauth) {
        const secret = speakeasy.generateSecret({
          name: `${config.appName} (${process.env.HOSTNAME || 'server'})`
        });

        req.session.setupTotpSecret = secret.base32;
        req.session.setupTotpOtpauth = secret.otpauth_url;
      }

      const qrCodeDataUrl = await QRCode.toDataURL(req.session.setupTotpOtpauth);

      res.render('setup', {
        qrCodeDataUrl
      });
    })
  );

  app.post(
    '/setup',
    asyncHandler(async (req, res) => {
      if (store.hasUsers()) {
        res.redirect('/login');
        return;
      }

      const username = String(req.body.username || '').trim();
      const submittedPassword = String(req.body.password || '');
      const otpCode = String(req.body.otpCode || '').replace(/\s+/g, '');

      if (!username || !submittedPassword || !otpCode) {
        setFlash(req, 'error', 'All setup fields are required.');
        res.redirect('/setup');
        return;
      }

      if (!req.session.setupTotpSecret) {
        setFlash(req, 'error', 'Setup session expired. Reload and try again.');
        res.redirect('/setup');
        return;
      }

      const otpValid = speakeasy.totp.verify({
        secret: req.session.setupTotpSecret,
        encoding: 'base32',
        token: otpCode,
        window: 1
      });

      if (!otpValid) {
        setFlash(req, 'error', 'Invalid TOTP code.');
        res.redirect('/setup');
        return;
      }

      const passwordHash = await bcrypt.hash(submittedPassword, 12);

      store.createUser({
        username,
        passwordHash,
        totpSecret: req.session.setupTotpSecret
      });

      clearSetupSecret(req);
      await regenerateSession(req);

      setFlash(req, 'success', 'Account created. Sign in to continue.');
      res.redirect('/login');
    })
  );

  app.get('/login', (req, res) => {
    if (!store.hasUsers()) {
      res.redirect('/setup');
      return;
    }

    if (req.session.authenticatedUserId) {
      res.redirect('/');
      return;
    }

    res.render('login');
  });

  app.post(
    '/login',
    asyncHandler(async (req, res) => {
      if (!store.hasUsers()) {
        res.redirect('/setup');
        return;
      }

      const username = String(req.body.username || '').trim();
      const submittedPassword = String(req.body.password || '');

      const user = store.findUserByUsername(username);
      if (!user) {
        setFlash(req, 'error', 'Invalid username or password.');
        res.redirect('/login');
        return;
      }

      const validPassword = await bcrypt.compare(submittedPassword, user.passwordHash);
      if (!validPassword) {
        setFlash(req, 'error', 'Invalid username or password.');
        res.redirect('/login');
        return;
      }

      await regenerateSession(req);
      req.session.pendingMfaUserId = user.id;
      await saveSession(req);
      res.redirect('/mfa');
    })
  );

  app.get('/mfa', (req, res) => {
    if (!req.session.pendingMfaUserId) {
      res.redirect('/login');
      return;
    }

    res.render('mfa');
  });

  app.post(
    '/mfa',
    asyncHandler(async (req, res) => {
      const pendingId = req.session.pendingMfaUserId;
      if (!pendingId) {
        res.redirect('/login');
        return;
      }

      const otpCode = String(req.body.otpCode || '').replace(/\s+/g, '');
      const user = store.findUserById(pendingId);

      if (!user) {
        req.session.pendingMfaUserId = null;
        setFlash(req, 'error', 'Login session expired. Please sign in again.');
        res.redirect('/login');
        return;
      }

      const validOtp = speakeasy.totp.verify({
        secret: user.totpSecret,
        encoding: 'base32',
        token: otpCode,
        window: 1
      });

      if (!validOtp) {
        setFlash(req, 'error', 'Invalid MFA code.');
        res.redirect('/mfa');
        return;
      }

      await regenerateSession(req);
      req.session.authenticatedUserId = user.id;
      await saveSession(req);
      res.redirect('/');
    })
  );

  app.post('/logout', (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('argus_sid', {
        path: '/',
        httpOnly: true,
        sameSite: sessionCookieOptions.sameSite,
        secure: sessionCookieOptions.secure
      });
      res.clearCookie(sessionCookieName, {
        path: '/',
        httpOnly: true,
        sameSite: sessionCookieOptions.sameSite,
        secure: sessionCookieOptions.secure
      });
      res.redirect('/login');
    });
  });
}

module.exports = {
  registerAuthRoutes
};
