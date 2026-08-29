FROM node:22-slim

ARG DSH_VERSION=0.1.1-rc.2
WORKDIR /opt/dsh-passwords

RUN apt-get update \
  && apt-get install -y --no-install-recommends git python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

RUN npm install -g pnpm@10

RUN mkdir -p /opt/dsh \
  && printf '%s\n' '{"name":"bundled-dsh","private":true,"pnpm":{"onlyBuiltDependencies":["@deepseek-ai/dsh-subprocess-local","@google/genai","koffi","node-pty","protobufjs"]}}' > /opt/dsh/package.json \
  && printf 'node-linker=hoisted\n' > /opt/dsh/.npmrc \
  && pnpm --dir /opt/dsh add @deepseek-ai/dsh@${DSH_VERSION}

COPY package.json package-lock.json tsconfig.json cordis.yml ./
RUN npm ci --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
COPY .env.example README.md README_en.md LICENSE ./
RUN npm run build

COPY docker/docker-entrypoint.bundled.sh /usr/local/bin/dsh-passwords-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/dsh-passwords-entrypoint \
  && chmod 755 /usr/local/bin/dsh-passwords-entrypoint \
  && mkdir -p /data/dsh /data/dsh-passwords \
  && chown -R node:node /opt/dsh /opt/dsh-passwords /data

ENV PATH=/opt/dsh/node_modules/.bin:/opt/dsh-passwords/node_modules/.bin:${PATH}
ENV DSH_HOME=/data/dsh
ENV DSH_PASSWORDS_ENV_FILE=/data/dsh-passwords/.env
ENV DSH_PASSWORDS_RUNTIME=docker
ENV MCP_DSH_ROOT=/opt/dsh/node_modules/@deepseek-ai/dsh
ENV MCP_DB_PATH=/data/dsh-passwords/platform.db
ENV MCP_GATEWAY_AUTO_TLS=0
ENV MCP_GATEWAY_HOST=0.0.0.0
ENV MCP_GATEWAY_PORT=3088
ENV MCP_GATEWAY_UPSTREAM=http://127.0.0.1:3080
ENV MCP_DSH_RESTART_SERVICE=

EXPOSE 3088
ENTRYPOINT ["dsh-passwords-entrypoint"]
