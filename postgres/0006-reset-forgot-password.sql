-- Creates password reset token which will be sent to the user's email
CREATE OR REPLACE FUNCTION user_password_reset_request(_email VARCHAR(255))
RETURNS SETOF user_status AS 
$$
DECLARE
  fn_status VARCHAR(255);
  active_password_reset_count INT;
BEGIN
  -- Check new email address format
  IF NOT _email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Invalid email format. Please use a valid email address.';
  END IF;

  -- Check if there is an active password reset request
  SELECT COUNT(*) INTO active_password_reset_count
  FROM user_password_reset
  WHERE email = _email AND created_at > NOW() - interval '20 minutes';

  IF active_password_reset_count > 0 THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='You currently have an active password reset request. Please check your email.';
  END IF;

  -- Create new password reset request entry
  INSERT INTO user_password_reset(email, token)
    VALUES (_email, gen_random_uuid()::VARCHAR);

  SELECT 'A password reset request has been made. Please check your email for more information.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$ LANGUAGE plpgsql;

-- Verify password reset token and update password
CREATE OR REPLACE FUNCTION user_password_reset_verify(_email VARCHAR(255), _token VARCHAR(255), _new_password VARCHAR(255))
RETURNS SETOF user_status AS 
$$
DECLARE
  fn_status VARCHAR(255);
  user_id INT;
  active_password_reset_count INT;
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
  WHERE email = _email;

  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='No matching email and token found.';
  END IF;

  -- Check if there is an active password reset request
  SELECT COUNT(*) INTO active_password_reset_count
  FROM user_password_reset
  WHERE email = _email AND token = _token AND created_at > NOW() - interval '20 minutes';

  IF active_password_reset_count < 1 THEN
    RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='There was a problem with your password reset, please try again. If the problem persists, please try requesting a new password reset email.';
  END IF;

  -- Update user's password with new password
  UPDATE users
    SET password = crypt(_new_password, gen_salt('bf'))
    WHERE id = user_id;

  SELECT 'Your password has been successfully reset. Please login to continue.' INTO fn_status;
  RETURN QUERY SELECT fn_status as status;
END;
$$ LANGUAGE plpgsql;
