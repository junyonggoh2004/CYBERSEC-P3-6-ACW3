FROM httpd:2.4.68

# Enable mod_dav and mod_dav_fs (both required; fs depends on dav)
RUN sed -i \
  -e 's|^#LoadModule dav_module|LoadModule dav_module|' \
  -e 's|^#LoadModule dav_fs_module|LoadModule dav_fs_module|' \
  conf/httpd.conf

# Prepare DavLockDB location and the WebDAV collection directory.
# NOTE: this httpd image runs its worker processes as www-data (see the
# User/Group directives in httpd.conf), NOT daemon. The state dirs must be
# owned by www-data or mod_dav fails with "Could not open the lock database"
# (HTTP 500) on the first PUT. (Older httpd images used daemon.)
RUN mkdir -p var htdocs/webdav \
  && chown -R www-data:www-data var htdocs/webdav

# Append WebDAV configuration. ServerName silences the AH00558 startup warning
# so the demo output stays clean.
RUN printf '\n\
ServerName localhost\n\
DavLockDB /usr/local/apache2/var/DavLock\n\
<Directory "/usr/local/apache2/htdocs/webdav">\n\
    Dav On\n\
    Require all granted\n\
</Directory>\n' >> conf/httpd.conf
