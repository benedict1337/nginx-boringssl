FROM alpine:latest AS build

ARG BUILD

ARG NGX_MAINLINE_VER=1.29.1
ARG BORINGSSL_VER=main
ARG MODSEC_VER=v3.0.14
ARG NGX_BROTLI=master
ARG NGX_HEADERS_MORE=v0.39
ARG NGX_NJS=0.9.2
ARG NGX_MODSEC=v1.0.4
ARG NGX_GEOIP2=3.4
ARG NGX_TLS_DYN_SIZE=nginx__dynamic_tls_records_1.27.5+.patch

WORKDIR /src

# Install the required packages

RUN apk add --no-cache \
        ca-certificates \
        build-base \ 
        patch \
        cmake \ 
        git \
        libtool \
        autoconf \
        automake \
        libatomic_ops-dev \
        zlib-dev \
        pcre2-dev \
        linux-headers \ 
        yajl-dev \
        libxml2-dev \ 
        libxslt-dev \
        perl-dev \
        perl \
        curl-dev \
        lmdb-dev \
        geoip-dev \
        ninja \
        libunwind-dev \
        go \
        libmaxminddb-dev \
        libfuzzy2-dev 

# BoringSSL
   
RUN (git clone --depth 1 --recursive --branch "$BORINGSSL_VER" https://boringssl.googlesource.com/boringssl /src/boringssl \
        && cd /src/boringssl \
        && cmake -GNinja -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release \
        && ninja -C build \
        && mkdir -p /src/boringssl/.openssl/lib \
        && ln -s /src/boringssl/include /src/boringssl/.openssl/include \
        && cp /src/boringssl/build/libcrypto.a /src/boringssl/.openssl/lib/ \
        && cp /src/boringssl/build/libssl.a /src/boringssl/.openssl/lib/)

# ModSecurity

RUN (git clone --depth 1 --recursive --branch "$MODSEC_VER" https://github.com/SpiderLabs/ModSecurity /src/ModSecurity \
        && sed -i "s|SecRuleEngine.*|SecRuleEngine On|g" /src/ModSecurity/modsecurity.conf-recommended \
        && sed -i "s|unicode.mapping|/etc/nginx/modsec/unicode.mapping|g" /src/ModSecurity/modsecurity.conf-recommended \
        && echo -e "Include /etc/nginx/modsec/modsecurity.conf\nInclude /etc/nginx/modsec/modsecurity-crs/crs-setup.conf\nInclude /etc/nginx/modsec/modsecurity-crs/rules/*.conf" > /src/ModSecurity/owasp-crs_main.conf \
        && cd /src/ModSecurity \
        && /src/ModSecurity/build.sh \
        && /src/ModSecurity/configure --with-pcre2 --with-lmdb \
        && make -j "$(nproc)" \
        && make -j "$(nproc)" install \
        && strip -s /usr/local/modsecurity/lib/libmodsecurity.so.3) 

# OWASP-CRS

RUN (git clone --depth 1 --recursive --branch v4.0/main https://github.com/coreruleset/coreruleset /src/modsecurity-crs \
        && cp /src/modsecurity-crs/crs-setup.conf.example /src/modsecurity-crs/crs-setup.conf \
        && cp /src/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /src/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf \
        && rm -rf /src/modsecurity-crs/.git \
        && rm -rf /src/modsecurity-crs/.github \
        && find /src/modsecurity-crs/* ! -name 'crs-setup.conf' ! -path '/src/modsecurity-crs/rules' ! -path '/src/modsecurity-crs/rules/*' -exec rm -rf {} +)

# Modules

RUN (git clone --depth 1 --recursive --branch "$NGX_BROTLI" https://github.com/google/ngx_brotli /src/ngx_brotli \
        && git clone --depth 1 --recursive --branch "$NGX_HEADERS_MORE" https://github.com/openresty/headers-more-nginx-module /src/headers-more-nginx-module \
        && git clone --depth 1 --recursive --branch "$NGX_NJS" https://github.com/nginx/njs /src/njs \
        && git clone --depth 1 --recursive --branch "$NGX_MODSEC" https://github.com/SpiderLabs/ModSecurity-nginx /src/ModSecurity-nginx \
        && git clone --depth 1 --recursive --branch "$NGX_GEOIP2" https://github.com/leev/ngx_http_geoip2_module /src/ngx_http_geoip2_module) 

# Nginx

RUN (wget https://nginx.org/download/nginx-"$NGX_MAINLINE_VER".tar.gz -O - | tar xzC /src \
        && mv /src/nginx-"$NGX_MAINLINE_VER" /src/nginx \
        && wget https://raw.githubusercontent.com/nginx-modules/ngx_http_tls_dyn_size/master/"$NGX_TLS_DYN_SIZE" -O /src/nginx/dynamic_tls_records.patch \
        && sed -i "s|nginx/|NGINX-BoringSSL with ModSec/|g" /src/nginx/src/core/nginx.h \
        && sed -i "s|Server: nginx|Server: NGINX-BoringSSL with ModSec|g" /src/nginx/src/http/ngx_http_header_filter_module.c \
        && sed -i "s|<hr><center>nginx</center>|<hr><center>NGINX-BoringSSL with ModSec</center>|g" /src/nginx/src/http/ngx_http_special_response.c \
        && cd /src/nginx \
        && patch -p1 < dynamic_tls_records.patch) 
RUN cd /src/nginx \
    && ./configure \
        --build=${BUILD} \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --http-client-body-temp-path=/var/cache/nginx/client_temp \
        --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
        --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
        --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
        --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
        --user=nginx \
        --group=nginx \
        --with-compat \
        --with-threads \
        --with-file-aio \
        --with-libatomic \
        --with-pcre \
        --without-poll_module \
        --without-select_module \
        --with-openssl="/src/boringssl" \
        --with-cc-opt="-I/src/boringssl/.openssl/include -Wno-error -Wno-deprecated-declarations -fPIC" \
        --with-ld-opt="-L/src/boringssl/.openssl/lib -lssl -lcrypto -lstdc++" \
        --with-mail=dynamic \
        --with-mail_ssl_module \
        --with-stream=dynamic \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-stream_realip_module \
        --with-stream_geoip_module=dynamic \
        --with-http_v2_module \
        --with-http_v3_module \
        --with-http_ssl_module \
        --with-http_perl_module=dynamic \
        --with-http_geoip_module=dynamic \
        --with-http_realip_module \
        --with-http_gunzip_module \
        --with-http_addition_module \
        --with-http_gzip_static_module \
        --with-http_auth_request_module \
        --add-dynamic-module=/src/ngx_brotli \
        --add-dynamic-module=/src/headers-more-nginx-module \
        --add-dynamic-module=/src/njs/nginx \
        --add-dynamic-module=/src/ModSecurity-nginx \
        --add-dynamic-module=/src/ngx_http_geoip2_module \
    && touch /src/boringssl/.openssl/include/openssl/ssl.h \
    && make -j "$(nproc)" \
    && make -j "$(nproc)" install \
    && rm /src/nginx/*.patch \
    && strip -s /usr/sbin/nginx \
    && strip -s /usr/lib/nginx/modules/*.so

FROM python:alpine AS production

COPY --from=build /etc/nginx /etc/nginx 
COPY --from=build /usr/sbin/nginx   /usr/sbin/nginx
COPY --from=build /usr/lib/nginx /usr/lib/nginx
COPY --from=build /usr/local/lib/perl5  /usr/local/lib/perl5
COPY --from=build /usr/lib/perl5/core_perl/perllocal.pod    /usr/lib/perl5/core_perl/perllocal.pod
COPY --from=build /usr/local/modsecurity/lib/libmodsecurity.so.3    /usr/local/modsecurity/lib/libmodsecurity.so.3

COPY assets/nginx.conf /etc/nginx/nginx.conf
COPY assets/default.conf /etc/nginx/conf.d/default.conf
COPY assets/index.html /etc/nginx/html/index.html

RUN addgroup -S nginx \
    && adduser -D -S -h /var/cache/nginx -s /sbin/nologin -G nginx nginx
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    tini \
    zlib \
    pcre2 \
    lmdb \
    libstdc++ \ 
    yajl \
    libxml2 \ 
    libxslt \
    libfuzzy2 \
    perl \
    libcurl \
    geoip \
    libmaxminddb-libs 
RUN mkdir -p /var/log/nginx/ \
    && mkdir -p /etc/nginx/modsec \
    && touch /var/log/nginx/access.log \
    && touch /var/log/nginx/error.log \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && ln -s /usr/lib/nginx/modules /etc/nginx/modules

COPY --from=build /src/ModSecurity/unicode.mapping  /etc/nginx/modsec/unicode.mapping
COPY --from=build /src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
COPY --from=build /src/modsecurity-crs /etc/nginx/modsec/modsecurity-crs
COPY --from=build /src/ModSecurity/owasp-crs_main.conf /etc/nginx/modsec/owasp-crs_main.conf

LABEL maintainer="Bence Kócsi <info@benedict-system.eu>"

EXPOSE 80 443 443/udp

ENTRYPOINT ["tini", "--", "nginx"]
CMD ["-g", "daemon off;"]