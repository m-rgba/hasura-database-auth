-- Refresh function - returns `access` and `refresh` tokens
-- Leverages Hasura permissions. Takes the refresh token for authentication, this function is only accessible to the `refresh` role.
-- Defaults to the `user_id` passed through the refresh JWT to default the `user_id` passed to the function.
-- The functions checks to make sure the user is active and passes back a new set of tokens.
CREATE OR REPLACE FUNCTION user_refresh_tokens()
RETURNS SETOF user_tokens AS
$$
DECLARE
  access_token VARCHAR(255);
  refresh_token VARCHAR(255);
  user_id INT;
  user_role VARCHAR(255);
  user_is_enabled BOOLEAN;
  user_email_verified BOOLEAN;
  access_expiry_date TIMESTAMP;
  refresh_expiry_date TIMESTAMP;
  jwt_secret TEXT;
BEGIN
  -- Check if the username or email exists in the users table
  SELECT id, role, email_verified, is_enabled INTO user_id, user_role, user_email_verified, user_is_enabled
  FROM users
  WHERE id = (hasura_session ->> 'x-hasura-user-id')::INT;

  -- Validate the user
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='There was a problem logging in with your provided credentials. Please check your email / username and password pair and try again.';
  END IF;
  IF NOT user_is_enabled THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Your account has been disabled. Please contact an administrator for more information.';
  END IF;
  IF NOT user_email_verified THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Your email has not been verified. Please verify your email before logging in.';
  END IF;

  -- Set the expiry date for the access and refresh tokens
  SELECT NOW() + interval '5 minutes' INTO access_expiry_date;
  SELECT NOW() + interval '1 hour' INTO refresh_expiry_date;
  -- Get the JWT secret
  SELECT current_setting('env.POSTGRES_JWT_SECRET') INTO jwt_secret;

  -- Generate the JWT access and refresh tokens
  SELECT
  -- Access token
  sign(
    json_build_object(
      'iss', 'hasuradb',
      'aud', 'client',
      'exp', to_char(access_expiry_date, 'YYYY-MM-DD HH24:MI:SS'),
      'token', 'access',
      'https://hasura.io/jwt/claims', json_build_object(
        'x-hasura-allowed-roles', array_to_json(ARRAY[user_role]),
        'x-hasura-default-role', user_role,
        'x-hasura-user-id', user_id
      )
    ),
    jwt_secret
  ) AS access_token,
  -- Refresh token
  sign(
    json_build_object(
      'iss', 'hasuradb',
      'aud', 'client',
      'exp', to_char(refresh_expiry_date, 'YYYY-MM-DD HH24:MI:SS'),
      'token', 'refresh',
      'https://hasura.io/jwt/claims', json_build_object(
        'x-hasura-allowed-roles', '["public"]',
        'x-hasura-default-role', 'public',
        'x-hasura-user-id', user_id
      )
    ),
    jwt_secret
  ) AS refresh_token
  INTO access_token, refresh_token;
  
  -- Return the JWT access and refresh tokens
  RETURN QUERY SELECT access_token, refresh_token;
END;
$$
LANGUAGE plpgsql;