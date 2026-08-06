FROM registry.internal/base:1.14.3
WORKDIR /srv/app
ENV REGISTRY_PASSWORD={{PWA_24_140}}
ENV NPM_TOKEN={{NPMTOKEN_0_141}}
ENV ARTIFACT_TOKEN={{B64_40_142}}
RUN curl -sSf -H "Authorization: Bearer {{B64URL_43_143}}" https://artifacts.internal/app.tar.gz -o app.tar.gz
RUN curl -sSf -H "Authorization: Basic {{B64_44_144}}" https://artifacts.internal/deps.tar.gz -o deps.tar.gz
RUN wget --header="Authorization: Bearer {{B64URL_43_145}}" -O plugins.tar.gz https://artifacts.internal/plugins.tar.gz
RUN echo "machine artifacts.internal login ci password {{PWA_20_146}}" > /root/.netrc
ARG DEPLOY_KEY_PASSPHRASE={{PWP_20_147}}
ARG REGISTRY_PASSWORD
ENV NPM_TOKEN_REF=${NPM_TOKEN}
RUN --mount=type=secret,id=npm_token npm ci --ignore-scripts
ENV PATH=/srv/app/bin:/usr/local/bin:/usr/bin:/bin
LABEL org.opencontainers.image.revision=4d9a7c1e83b25f60d1ea94c73f0b6a25e8c1d947
COPY . /srv/app
CMD ["/srv/app/bin/api"]
