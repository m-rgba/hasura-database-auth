#!/bin/bash

# Loads up the JWT secret as an env variable.
# Accessible in SQL via `current_setting('env.POSTGRES_JWT_SECRET')`
psql -U ${POSTGRES_USER} <<-END
  ALTER DATABASE ${POSTGRES_DB} SET "env.POSTGRES_JWT_SECRET" TO ${POSTGRES_JWT_SECRET};
END