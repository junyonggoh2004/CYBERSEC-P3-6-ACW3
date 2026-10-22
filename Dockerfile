FROM httpd:2.4.68

# Enable mod_dav and mod_dav_fs (both required; fs depends on dav)
RUN sed -i \
  -e 's|^#LoadModule dav_module|LoadModule dav_module|' \
  -e 's|^#LoadModule dav_fs_module|LoadModule dav_fs_module|' \
  conf/httpd.conf

# Prepare DavLockDB location and the WebDAV collection directory,
# owned by the daemon user so httpd can write lock + property state
RUN mkdir -p var htdocs/webdav \
  && chown -R daemon:daemon var htdocs/webdav

# Append WebDAV configuration
RUN printf '\n\
DavLockDB /usr/local/apache2/var/DavLock\n\
<Directory "/usr/local/apache2/htdocs/webdav">\n\
    Dav On\n\
    Require all granted\n\
</Directory>\n' >> conf/httpd.conf
