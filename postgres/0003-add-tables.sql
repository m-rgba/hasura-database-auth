-- Setup tables

-- We'll be using Hasura's enums to help us create an manage our roles - more info:
-- https://hasura.io/docs/latest/schema/postgres/enums/#pg-create-enum-table
CREATE TABLE user_role (
  value text PRIMARY KEY,
  comment text
);

INSERT INTO user_role (value, comment) VALUES
  ('user', 'Base user role.'),
  ('manager', 'User + ability to edit users.');


-- These tables are used as placeholders for returning data from functions
CREATE TABLE user_tokens (
  access_token VARCHAR(255), 
  refresh_token VARCHAR(255)
);

CREATE TABLE user_status (
  status VARCHAR(255)
);

-- Base tables for user management
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  role VARCHAR(255) NOT NULL DEFAULT 'user',
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  email_verified BOOLEAN DEFAULT false,
  is_enabled BOOLEAN DEFAULT true,
  CONSTRAINT fk_role FOREIGN KEY (role) REFERENCES user_role (value)
);

CREATE TABLE user_email_verify (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  token VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE user_email_update_verify (
  id SERIAL PRIMARY KEY,
  old_email VARCHAR(255) NOT NULL,
  new_email VARCHAR(255) NOT NULL,
  token VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE user_password_reset (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  token VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Updates `updated_at` column in the `users` table
CREATE OR REPLACE FUNCTION update_updated_at_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE update_updated_at_timestamp();