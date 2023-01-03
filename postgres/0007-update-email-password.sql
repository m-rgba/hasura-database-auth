-- Update email - leverages Hasura.
-- Only available if user is logged in, defaults to their `user id`, takes a `new_email` as an argument.
-- Checks to make sure the new email currently isn't in use and throws an error if it is.
CREATE OR REPLACE FUNCTION user_update_email_request(_new_email VARCHAR(255))
RETURNS SETOF user_status AS 
$$
DECLARE
  fn_status VARCHAR(255);
  user_old_email VARCHAR(255);
  email_usage_count INT;
BEGIN
  -- Check new email address format
  IF NOT _new_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Invalid email format. Please use a valid email address.';
  END IF;

  -- Check new email address
  SELECT COUNT(*) INTO email_usage_count
  FROM users
  WHERE email = _new_email;

  IF email_usage_count > 0 THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Your new email is currently registered to another user, please try again.';
  END IF;

  -- Get old email from current signed in user
  SELECT email INTO user_old_email
  FROM users
  WHERE id = (hasura_session ->> 'x-hasura-user-id')::INT;

  -- Create new email update request
  INSERT INTO user_email_update_verify(old_email, new_email, token)
    VALUES (user_old_email, _new_email, gen_random_uuid()::VARCHAR);

  SELECT 'An validation email has been sent to your email. Please follow instructions for validating and updating your account.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$ LANGUAGE plpgsql;

-- Verify email using the token generated for the user on create / edit and their email
-- This will update the `user` table `email_verified` column to true
CREATE OR REPLACE FUNCTION user_update_email_verify(_new_email VARCHAR(255), _token VARCHAR(255))
RETURNS SETOF user_status AS 
$$
DECLARE
  fn_status VARCHAR(255);
  user_old_email VARCHAR(255);
  email_usage_count INT;
BEGIN
  -- Check new email address
  SELECT COUNT(*) INTO email_usage_count
  FROM users
  WHERE email = _new_email;

  IF email_usage_count > 0 THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Your new email is currently registered to another user, please try again.';
  END IF;

  -- Check new email address
  SELECT old_email INTO user_old_email
  FROM user_email_update_verify
  WHERE new_email = _new_email AND token = _token;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='No matching email and token found.';
  END IF;

  UPDATE users
    SET email = _new_email
    WHERE email = user_old_email;

  SELECT 'Your email has been validated and your account has been updated with your desired address.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$ LANGUAGE plpgsql;

-- Update password - leverages Hasura.
-- Only available if user is logged in, defaults to their `user id` - takes their current password as an input, looks up the user to confirm and then sets the password as the new password.
CREATE OR REPLACE FUNCTION user_update_password(_current_password VARCHAR(255), _new_password VARCHAR(255))
RETURNS SETOF user_status AS 
$$
DECLARE
  fn_status VARCHAR(255);
  user_id INT;
BEGIN
  -- Check new password strength
  -- Check the length of the password
  IF LENGTH(_new_password) <= 6 THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password is not long enough. Password must contain at least 6 characters.';
  END IF;
  -- Check for the presence of lowercase letters
  IF NOT _new_password ~* '[a-z]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one lowercase letter.';
  END IF;
  -- Check for the presence of uppercase letters
  IF NOT _new_password ~* '[A-Z]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one uppercase letter.';
  END IF;
  -- Check for the presence of numbers
  IF NOT _new_password ~* '[0-9]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one number.';
  END IF;
  -- Check for the presence of special characters
  IF NOT _new_password ~* '[^A-Za-z0-9]' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password must contain at least one special character.';
  END IF;
  -- Check for any blacklisted passwords
  -- You could probably make this a table and check against that instead as well
  IF _new_password = ANY (ARRAY[
    'Password123!', '123Password!', 'Abc123!', 'Abc123!'
  ]) THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Password has been blacklisted, please try another one.';
  END IF;

  -- Make sure the account exists which we're updating the password for
  SELECT id INTO user_id
  FROM users
  WHERE id = (hasura_session ->> 'x-hasura-user-id')::INT AND password = crypt(_current_password, gen_salt('bf'));

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Your current password does not match your existing password.';
  END IF;

  UPDATE users
    SET password = crypt(_new_password, gen_salt('bf'))
    WHERE id = user_id;

  SELECT 'Your account has been updated with your desired password. You can now use it for signing into your account.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$ LANGUAGE plpgsql;
