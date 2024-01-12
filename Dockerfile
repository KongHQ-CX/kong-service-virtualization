FROM kong/kong-gateway:3.5.0.2

USER root

# Add plugin bundles
COPY src /usr/local/share/lua/5.1/kong/plugins/kong-service-virtualization

# Patch "bundled" plugins table to enable by default
RUN sed '20 a "kong-service-virtualization",' /usr/local/share/lua/5.1/kong/constants.lua > /usr/local/share/lua/5.1/kong/constants.lua.patch && \
    mv /usr/local/share/lua/5.1/kong/constants.lua.patch /usr/local/share/lua/5.1/kong/constants.lua

USER kong
