-- `users` create / signup
CREATE OR REPLACE FUNCTION user_signup(_username VARCHAR(50), _email VARCHAR(255), _password VARCHAR(255))
RETURNS SETOF user_status AS
$$
DECLARE
  fn_status VARCHAR(255);
BEGIN
  -- Check password strength and username / email validity
  -- Check that the username is alphanumeric with underscores only
  IF NOT _username ~* '^[a-zA-Z0-9_]+$' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Username must be alphanumeric with underscores only.';
  END IF;
  -- Check that the email is in a valid format
  IF NOT _email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Invalid email format. Please use a valid email address.';
  END IF;

  -- Check the length of the password
  IF LENGTH(_password) <= 6 THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password is not long enough. Password must contain at least 6 characters.';
  END IF;
  -- Check for the presence of lowercase letters
  IF NOT _password ~* '[a-z]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one lowercase letter.';
  END IF;
  -- Check for the presence of uppercase letters
  IF NOT _password ~* '[A-Z]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one uppercase letter.';
  END IF;
  -- Check for the presence of numbers
  IF NOT _password ~* '[0-9]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one number.';
  END IF;
  -- Check for the presence of special characters
  IF NOT _password ~* '[^A-Za-z0-9]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one special character.';
  END IF;
  -- Check for any blacklisted passwords
  -- You could probably make this a table and check against that instead as well
  IF _password = ANY (ARRAY[
    'Password123!', '123Password!', 'Abc123!', 'Abc123!'
  ]) THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password has been blacklisted, please try another one.';
  END IF;

  -- Insert the new user
  INSERT INTO users (username, email, password)
    VALUES (_username, _email, crypt(_password, gen_salt('bf')));

  -- Generate email verification request
  INSERT INTO user_email_verify (email, token)
    VALUES (_email, gen_random_uuid()::VARCHAR);

  SELECT 'User created successfully. Please check your email to validate the address.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$
LANGUAGE plpgsql;

-- Verify email using the token generated for the user on create / edit and their email
-- This will update the `user` table `email_verified` column to true
CREATE OR REPLACE FUNCTION user_signup_verify_email(_email VARCHAR(255), _token VARCHAR(255))
RETURNS SETOF user_status AS
$$
DECLARE
  fn_status VARCHAR(255);
  user_email VARCHAR(255);
BEGIN
  SELECT email INTO user_email
  FROM user_email_verify
  WHERE email = _email AND token = _token;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='No matching email and token found.';
  END IF;

  UPDATE users
    SET email_verified = true
    WHERE email = user_email;

  SELECT 'Email validated successfully. Your may now login to continue.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$ LANGUAGE plpgsql;

-- User login function - returns `access` and `refresh` tokens
CREATE OR REPLACE FUNCTION user_login(_username VARCHAR(50), _password VARCHAR(255))
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
  WHERE (username = _username OR email = _username) AND password = crypt(_password, password);

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