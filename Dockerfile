FROM python:3.12-slim

WORKDIR /app

# Install git for update checker
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir hatchling build

# Install wombat-core from the local sibling package (pass/).
# This must happen before wombat-server is installed so that
# `from wombat.control_schema import WizardControl` resolves correctly.
COPY pass/ /tmp/wombat-core/
RUN pip install --no-cache-dir /tmp/wombat-core && rm -rf /tmp/wombat-core

COPY wafpass-server/pyproject.toml wafpass-server/VERSION wafpass-server/README.md ./
COPY wafpass-server/wombat_server/ wombat_server/
COPY wafpass-server/alembic/ alembic/
COPY wafpass-server/alembic.ini wafpass-server/entrypoint.sh ./

RUN pip install --no-cache-dir ".[qr]" && chmod +x entrypoint.sh

# Copy Wombat control YAML files so the sandbox engine can find them.
# The pass/ directory was already used to install wombat-core above, but the
# controls/ subdirectory is data (not Python code) and is not installed by pip.
COPY pass/controls/ /app/controls/

# Copy Wombat regulatory logo assets so the PDF reporter can render framework badges.
COPY pass/assets/ /app/assets/

# Copy Wombat framework repository for update checking
COPY framework/ /app/framework/

# Default controls path — override with WOMBAT_CONTROLS_DIR if you mount your
# own controls volume (e.g. for custom/enterprise controls).
ENV WOMBAT_CONTROLS_DIR=/app/controls

# Framework path for update checking
ENV WOMBAT_FRAMEWORK_DIR=/app/framework

# Asset path used by the PDF reporter for regulatory logos
ENV WOMBAT_ASSETS_DIR=/app/assets

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
