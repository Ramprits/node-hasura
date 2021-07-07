var express = require("express");
var router = express.Router();
var admin = require("firebase-admin");
require("dotenv").config();
var fetch = require("node-fetch");
const AUTH_URL = `https://identitytoolkit.googleapis.com/v1`;

/* Post register user. */
router.post("/register", async function (req, res) {
  try {
    const user = await admin.auth().createUser(req.body);
    await generateToken(user);
    res.status(201).json(user);
  } catch (error) {
    res.status(400).send(error.message);
  }
});

/* Post login user. */
router.post("/login", async function (req, res) {
  try {
    const { email, password } = req.body.input || req.body;
    const loginRequest = await fetch(
      `${AUTH_URL}/accounts:signInWithPassword?key=${process.env.API_KEY}`,
      {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
          returnSecureToken: true,
        }),
      }
    );
    const { idToken, localId } = await loginRequest.json();
    if (!idToken) {
      return res.status(400).json({
        message: "error happened"
      })
    }
    res.status(200).send({
      accessToken: idToken,
      userId: localId,
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

/* Post update user. */
router.post("/updateUser", async function (req, res, next) {
  try {
    let token = req.headers.authorization;
    const { displayName, photoUrl, user_type } = req.body;
    console.log(token);
    const updatedRequest = await fetch(
      `${AUTH_URL}/accounts:update?key=${process.env.API_KEY}`,
      {
        method: "POST",
        body: JSON.stringify({
          idToken: token,
          displayName,
          photoUrl,
          returnSecureToken: true,
        }),
      }
    );
    const { idToken, localId } = await updatedRequest.json();
    if (!localId) throw Error("sorry your profile does not updated");
    await admin.auth().setCustomUserClaims(localId, {
      "https://hasura.io/jwt/claims": {
        "x-hasura-allowed-roles": ["user"],
        "x-hasura-default-role": `${user_type}`,
        "x-hasura-user-id": localId,
      },
    });

    res.status(200).send({
      accessToken: idToken,
      id: localId,
    });
  } catch (error) {
    res.status(400).send(error.message);
  }
});

module.exports = router;

async function generateToken(user) {
  await admin.auth().setCustomUserClaims(user.uid, {
    "https://hasura.io/jwt/claims": {
      "x-hasura-allowed-roles": ["user"],
      "x-hasura-default-role": "user",
      "x-hasura-user-id": user.uid,
    },
  });
}

