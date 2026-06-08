# PostQuantum.Hybrid WebApiDemo
#
# IMPORTANT: the native ML-KEM / ML-DSA primitives require OpenSSL 3.5+. NO
# current .NET base image ships it — Debian/Ubuntu images are on OpenSSL 3.0 and
# even Azure Linux 3.0 is only on 3.3.5, both of which make MLKem.IsSupported /
# MLDsa.IsSupported false. The library would then fall back to BouncyCastle
# (per ADR 0012), which works — but we want this demo to exercise the native
# .NET 10 path so users see the real thing. So we bring OpenSSL 3.5 in
# ourselves via conda-forge and point the runtime loader at it. Same approach
# the PostQuantum.Jwt containers and the repo's CI use.
#
# Build context is the REPO ROOT (we reference ../../src). Build with:
#   docker build -f samples/WebApiDemo/Dockerfile -t pqhybrid-webapidemo .
#   docker run --rm -p 5080:8080 pqhybrid-webapidemo
#
# Then open http://localhost:5080/ in a browser — Swagger UI is mounted at
# the root, so users can hit /seal, /sign, and the public-key endpoints
# without writing curl. Or hit it from the shell:
#   curl http://localhost:5080/pub/kem-public-key
#   curl -X POST http://localhost:5080/seal \
#        -H "Content-Type: application/json" \
#        -d '{"plaintext":"hello hybrid PQC"}'
#   curl -X POST http://localhost:5080/sign \
#        -H "Content-Type: application/json" \
#        -d '{"data":"sign me"}'
#
# To God be the glory - 1 Corinthians 10:31.

# ---- build ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS build
WORKDIR /src

# Copy only what the demo needs to build:
#   - core library + ASP.NET Core integration
#   - analyzers project (Directory.Build.targets injects it into every build)
#   - root + samples Directory.Build files and global.json (SDK pin)
COPY global.json ./
COPY Directory.Build.props ./
COPY Directory.Build.targets ./
COPY src/PostQuantum.Hybrid/ src/PostQuantum.Hybrid/
COPY src/PostQuantum.Hybrid.AspNetCore/ src/PostQuantum.Hybrid.AspNetCore/
COPY src/PostQuantum.Hybrid.Analyzers/ src/PostQuantum.Hybrid.Analyzers/
COPY samples/Directory.Build.props samples/Directory.Build.props
COPY samples/WebApiDemo/ samples/WebApiDemo/

RUN dotnet restore samples/WebApiDemo/WebApiDemo.csproj
RUN dotnet publish samples/WebApiDemo/WebApiDemo.csproj \
        -c Release -f net10.0 -o /app --no-restore

# ---- OpenSSL 3.5 (the base image's 3.3.5 is too old for ML-KEM / ML-DSA) ----
FROM mcr.microsoft.com/dotnet/sdk:10.0-azurelinux3.0 AS openssl
# gawk: the miniforge installer needs awk, which the Azure Linux image omits.
RUN tdnf install -y gawk && tdnf clean all && \
    curl -fsSL https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -o /tmp/mf.sh && \
    bash /tmp/mf.sh -b -p /opt/conda && rm -f /tmp/mf.sh && \
    /opt/conda/bin/conda create -y -n pq -c conda-forge "openssl>=3.5" && \
    /opt/conda/bin/conda clean -afy

# ---- runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:10.0-azurelinux3.0 AS runtime
# Bring the OpenSSL 3.5 env (same path preserved so library RPATHs resolve) and
# put it first on the loader path so .NET's libcrypto/libssl resolve to 3.5+.
COPY --from=openssl /opt/conda/envs/pq /opt/conda/envs/pq
ENV LD_LIBRARY_PATH=/opt/conda/envs/pq/lib
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "PostQuantum.Hybrid.Samples.WebApiDemo.dll"]
