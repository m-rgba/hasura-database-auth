# Hasura Database Auth

## Features
- Email sign-up and login strategy using the database and Hasura.
- Username and email server-side validation.
- Server-side password strength tests and password blacklist.
- Email verification token generation and method for validating the email account.
- JWT-based login method with support for access and refresh tokens.
- Forgot / reset password facility to help with resetting passwords (w/ time-based expiry).
- Update email and password facility for logged in users (with email verification for email updates).
- Emails sent using an email service provider (ESP) [in this example SendGrid] which provides an API, Events, and request transformers in Hasura.

## Credit
- Thanks to:
  - Michel Pelletier: https://github.com/michelp/
    - https://github.com/michelp/pgjwt
  - Sander Hahn: https://github.com/sanderhahn
    - https://github.com/sander-io/hasura-jwt-auth

A lot of my ideas about what was possible for authentication in the database came from those projects, and we're cribbing Michel's PGJWT implementation for generating our JWT tokens.

## Getting Started
TBD

## Database Breakdown
- **Tables**
  - `users`
    - Stores core user profile data.
  - `user_role`
    - Used as an enum in Hasura, lists user roles (FK with `users`).
  - `user_email_verify`
    - Used for verifying emails of new users.
    - Triggers an email in the ESP from a Hasura Event.
  - `user_password_reset`
    - Used for verifying password reset requests.
    - Triggers an email in the ESP from a Hasura Event.
  - `user_email_update_verify`
    - Used for verifying email updates of existing users.
    - Triggers an email in the ESP from a Hasura Event.

- **Dummy Tables** (used for helping define return types for Hasura, no data is stored here in these)
  - `user_tokens`
  - `user_status`
- **Functions**
  - `user_signup`
    - Checks validity of email, username, and password.
    - Creates user in `users` table and an email verification request (+ token) in `user_email_verify`.
  - `user_signup_verify_email`
    - Takes email + token which the user received and updates their status in `users` as `email_verified`.
  - `user_login`
    - Returns an unstored JWT access and refresh token to be used in authorization headers.
    - The refresh token has a role of `refresh` assigned to it which is only allowed to access the `user_refresh_tokens` function
  - `user_refresh_tokens`
    - Generates a new `access_token` and `refresh_token`.
  - `user_password_reset_request`
    - Creates a new forgot password / password reset request (+ token) in `user_password_reset`.
  - `user_password_reset_verify`
    - If the correct token is provided, allows the user to update their password.
  - `user_update_email_request`
    - Creates a new email verification request (+ token) in `user_email_update_verify`.
  - `user_update_email_verify`
    - If the correct token is provided, allows the user to update their email address associated with their account.
  - `user_update_password`
    - If the correct current password is provided, allows the user to update their password associated with their account.

## GraphQL Usage

### Sign-Up
Signs up the user, and will add an entry in the `user_email_verify` table.\
From here an event will send off a validation email using a Hasura Event.

**GQL Query:**
```graphql
mutation signUp($_email: String = "", $_username: String = "", $_password: String = "") {
  user_signup(args: {_email: $_email, _username: $_username, _password: $_password}) {
    status
  }
}
```
**Variable:**
```json
{
  "_username": "[USERNAME]",
  "_password": "[PASSWORD]"
}
```

### Email Validation
The user will receive a token (/ link depending on your client) to validate their email account exists.\
This will update their `email_verified` column in the `users` table.

**GQL Query:**
```graphql
mutation signUpVerifyEmail($_email: String = "", $_token: String = "") {
  user_signup_verify_email(args: {_email: $_email, _token: $_token}) {
    status
  }
}
```
**Variable:**
```json
{
  "_email": "[EMAIL]",
  "_token": "[EMAILED_TOKEN]"
}
```

### Login
The access tokens and refresh token will be able to be used as `Authorization` headers later on.\
This system works on a short-lived access token, longer-lived refresh token model.\
The `refresh_token` has a role of `refresh` assigned to it which is only allowed to access the `refreshTokens` query.

**GQL Query:**
```graphql
query login($_username: String = "", $_password: String = "") {
  user_login(args: {_username: $_username, _password: $_password}) {
    access_token
    refresh_token
  }
}
```
**Variable:**
```json
{
  "_email": "[EMAIL]",
  "_username": "[USERNAME]",
  "_password": "[PASSWORD]"
}
```

### Refresh Tokens
Our longer lived refresh token will be used generate a new access / refresh token pair when the access token is expired.\
It will source the current user's information from their `refresh_token`.\
It'll then check to ensure the user has not been deactivated before generating a new token.

**GQL Query:**
```graphql
query refreshTokens {
  user_refresh_tokens {
    access_token
    refresh_token
  }
}
```
**Headers:**
```json
{
  "Authorization": "Bearer [refresh_token]"
}
```

### Forgot / Reset Password
Create a forgot / reset password request and token.\
A Hasura Event will send the token via an email service provider (ESP).

**GQL Query:**
```graphql
mutation resetPassword($_email: String = "") {
  user_password_reset_request(args: {_email: $_email}) {
    status
  }
}
```
**Variable:**
```json
  "_email": "[EMAIL]"
```

### Forgot / Reset Password Confirm
Takes the email and the token and if active, allows the user to update their account with a new password.

```graphql
mutation resetPasswordVerify($_email: String = "", $_token: String = "", $_new_password: String = "") {
  user_password_reset_verify(args: {_email: $_email, _token: $_token, _new_password: $_new_password}) {
    status
  }
}
```
**Variable:**
```json
  "_email": "[EMAIL]",
  "_token": "[TOKEN]",
  "_new_password": "[PASSWORD]"
```

### Request Email Update
Create an email verification request and token for updating the email on the account.\
A Hasura Event will send the token via an email service provider (ESP).

**GQL Query:**
```graphql
mutation updateEmail($_new_email: String = "") {
  user_update_email_request(args: {_new_email: $_new_email}) {
    status
  }
}
```
**Variable:**
```json
  "_new_email": "[EMAIL]"
```
**Headers:**
```json
{
  "Authorization": "Bearer [access_token]"
}
```

### Email Update Verification
Takes the email and the token and if active, allows the user to update their account with the new email.

**GQL Query:**
```graphql
mutation updateEmailVerify($_new_email: String = "", $_token: String = "") {
  user_update_email_verify(args: {_new_email: $_new_email, _token: $_token}) {
    status
  }
}
```
**Variable:**
```json
  "_new_email": "[EMAIL]",
  "_token": "[TOKEN]"
```

### Update Password
Validates the current user's current password and then allows them to update to a new password.

**GQL Query:**
```
mutation MyMutation($_current_password: String = "", $_new_password: String = "") {
  user_update_password(args: {_current_password: $_current_password, _new_password: $_new_password}) {
    status
  }
}
```
**Variable:**
```json
  "_current_password": "[PASSWORD]",
  "_new_password": "[PASSWORD]"
```
**Headers:**
```json
{
  "Authorization": "Bearer [access_token]"
}
```
