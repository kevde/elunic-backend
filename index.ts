const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const _ = require('lodash');
const app = express();
const port = 3000;

import { Request, Response } from 'express';

app.use(express.json())

const saltRounds = 10;

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password?: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

async function validatePassword(user: UserEntry, password: string) {
  const result = await bcrypt.compare(password, user.passwordhash);
  return result;
}

function getUserByUsername(name: string): UserEntry | undefined {
  return MEMORY_DB[name] || undefined;
}

function getUserByEmail(email: string): UserEntry | undefined {
  const matchedUser = _.find(MEMORY_DB, (user: UserEntry) => {
    return user.email === email;
  })
  return matchedUser || undefined;
}

// Request body -> UserDto
app.get('/register', async (req: Request<UserDto>, res: Response) => {
  const schema = joi.object({
    username: joi.string().alphanum().min(3).max(24).required(),
    email: joi.string().email().required(),
    type: joi.string().valid('user', 'admin').required(),
    password: joi
      .string()
      .regex(/[ -~]*[a-z][ -~]*/) // at least 1 lower-case
      .regex(/[ -~]*[A-Z][ -~]*/) // at least 1 upper-case
      .regex(/[ -~]*(?=[ -~])[^0-9a-zA-Z][ -~]*/) // basically: [ -~] && [^0-9a-zA-Z], at least 1 special character
      .min(5)
      .max(24)
      .required()
      .error(new Error('Your password must at least have 1 uppercase, 1 lowercase and 1 special character')),
  }).required();
  try {
    const validatedUser = await schema.validateAsync(req.body || {});
    const matchedInEmail = getUserByEmail(validatedUser.email);
    const matchedInUsername = getUserByUsername(validatedUser.username);

    if (matchedInEmail || matchedInUsername) {
      throw new Error('User already exists')
    }

    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(validatedUser.password, salt);

    // set user
    MEMORY_DB[validatedUser.username] = {
      email: validatedUser.email,
      type: validatedUser.type || 'user',
      salt,
      passwordhash: hash,
    };

    const responseUser: UserDto = {
      username: validatedUser.username,
      email: validatedUser.email,
      type: validatedUser.type
    }
    res.status(200).send(responseUser)
  } catch (error) {
    res.status(400).send(error.message);
  }
});

// Request body -> { username: string, password: string }
app.post('/login', async (req: Request, res: Response) => {
  try {
    const matchedUser = await getUserByUsername(req.body.username);
    if (!matchedUser) {
      throw new Error('User not found');
    }
    const isValid = await validatePassword(matchedUser, req.body.password);
    if (!isValid) {
      throw new Error('Password do not match');
    }

    const responseUser: UserDto = {
      username: req.body.username,
      email: matchedUser.email,
      type: matchedUser.type
    }
    res.status(200).send(responseUser);
  } catch (error) {
    res.status(401).send(error.message);
  }
  // Return 200 if username and password match
  // Return 401 else
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
