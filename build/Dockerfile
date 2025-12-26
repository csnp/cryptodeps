# Dockerfile for GoReleaser
# This is used by goreleaser to build Docker images

FROM alpine:3.19

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -g '' cryptodeps

# Copy binary from goreleaser
COPY cryptodeps /usr/local/bin/cryptodeps

# Switch to non-root user
USER cryptodeps

# Set working directory
WORKDIR /workspace

ENTRYPOINT ["cryptodeps"]
CMD ["--help"]
