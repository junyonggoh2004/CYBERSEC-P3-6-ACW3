# Vulnerable target for CVE-2026-73636 — Apache mod_auth_digest
# one-time-nonce capture-replay authentication bypass.
#
# 2.4.68 is the last release BEFORE the mod_auth_digest nonce/nonce-count
# rewrite (patch fc722c6, first shipped in 2.4.69). See RUNBOOK.md Step 1 for
# the mechanism analysis and what is confirmed vs. inferred.
FROM httpd:2.4.68

# --- Module ---------------------------------------------------------------
# mod_auth_digest ships with the image but is commented out by default.
# authn_core / authn_file / authz_core are already enabled in the stock
# httpd.conf, so Digest+file auth needs only this one module uncommented.
RUN sed -i 's|^#LoadModule auth_digest_module|LoadModule auth_digest_module|' \
  conf/httpd.conf

# --- Credentials ----------------------------------------------------------
# .htdigest line format is:  user:realm:MD5(user:realm:password)
# Generated here with md5sum (present in the Debian base) instead of the
# interactive `htdigest` binary, so the build is deterministic.
#   user   = alice
#   realm  = secret   (must match AuthName below exactly)
#   passwd = password123
RUN printf 'alice:secret:%s\n' \
      "$(printf '%s' 'alice:secret:password123' | md5sum | cut -d' ' -f1)" \
      > /usr/local/apache2/.htdigest \
  && chown www-data:www-data /usr/local/apache2/.htdigest \
  && chmod 640 /usr/local/apache2/.htdigest

# --- Protected resource ---------------------------------------------------
RUN mkdir -p htdocs/secret \
  && printf 'FLAG{digest-replay-demo} protected content, authorised users only.\n' \
       > htdocs/secret/index.html \
  && chown -R www-data:www-data htdocs/secret

# --- Digest auth config ---------------------------------------------------
# AuthDigestNonceLifetime 0  -> "one-time nonce": each nonce is meant to be
#   usable exactly once; reuse should be rejected 401 stale.
# AuthDigestShmemSize 1024   -> DEMO AID, not part of the vulnerability. The
#   client list that records spent nonces lives in this shared-memory segment.
#   A small segment makes entries easy to evict/GC so the replay window can be
#   induced reliably in a live demo. 1024 is near the module minimum.
# ServerName localhost       -> silences the AH00558 startup warning.
RUN printf '\n\
ServerName localhost\n\
AuthDigestShmemSize 1024\n\
<Directory "/usr/local/apache2/htdocs/secret">\n\
    AuthType Digest\n\
    AuthName "secret"\n\
    AuthDigestProvider file\n\
    AuthUserFile /usr/local/apache2/.htdigest\n\
    AuthDigestNonceLifetime 0\n\
    Require valid-user\n\
</Directory>\n' >> conf/httpd.conf
