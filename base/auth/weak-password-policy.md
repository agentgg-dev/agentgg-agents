---
slug: weak-password-policy
name: Weak Password Policy
description: Registration/password-change paths that accept short, common, or trivially-guessable passwords because no minimum-length, common-password-deny, or strength check is enforced before hashing. Walker mode reads the model/validator helpers to confirm the absence of enforcement.
version: 0.1.0
author: agentgg
mode: walker
noiseTier: precise
filePatterns:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs}"
  - "**/*.{py,rb,go,php,java,kt,cs}"
excludePatterns:
  - "**/__tests__/**"
  - "**/*.test.{ts,tsx,js,jsx,mjs,py,rb,go,java}"
  - "**/*.spec.{ts,tsx,js,jsx,mjs,py,rb,go,java}"
  - "**/node_modules/**"
preFilter:
  - regex: "(bcrypt|argon2|scrypt|pbkdf2)\\.(hash|hashSync)\\s*\\("
    label: "Password hashing call"
  - regex: "password\\s*:\\s*hash\\s*\\("
    label: "Storing hashed password"
  - regex: "(set|create|register|signup|signUp)Password"
    label: "Password setter / registration helper"
  - regex: "User\\.(create|register|signup|build)\\s*\\("
    label: "User creation"
maxTurnsPerBatch: 30
maxFilesPerBatch: 5
references:
  - CWE-521
  - OWASP-A07:2021
---

You are reviewing source code for weak password-policy enforcement —
registration or password-change paths that hash and store a password
the user supplied **without first** rejecting trivially-weak inputs
(too short, in the top-N common-password list, equal to the username
or email).

**Walker mode advantage:** the enforcement (or absence thereof) often
lives in a model setter (`User.init({ password: { set(...) { ... } } })`),
a validator helper (`lib/validators.ts`, `services/passwordPolicy.py`),
or a schema (Zod, Joi, class-validator). When you find a password
being hashed, Read the model and validator files before deciding.

## What to look for

**Direct hash without prior validation:**
```ts
// route handler
app.post("/register", async (req, res) => {
  const user = await User.create({
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 10),    // no length/strength check
  });
  ...
});
```

**Model setter that hashes but doesn't validate:**
```ts
// models/user.ts
User.init({
  password: {
    type: DataTypes.STRING,
    set(plain: string) {
      this.setDataValue("password", security.hash(plain));   // no length check
    },
  },
});
```

**Schema with no constraints on `password`:**
```ts
// Zod
const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string(),                                   // no .min(), no .refine()
});
```

```python
# Pydantic
class Register(BaseModel):
    email: EmailStr
    password: str                                         # no Field(min_length=...)
```

**Patterns that, if PRESENT in the chain from request to hash, mean a
policy is enforced (don't flag):**
- Length check ≥ 8 (preferably ≥ 10): `password.length >= 10`,
  `min_length=10`, `z.string().min(10)`.
- Common-password deny list:
  `validatePasswordIsNotInTopOneMillionCommonPasswordsList(...)`,
  `zxcvbn(password).score >= 3`, `topNCommonPasswords.has(...)`.
- Equality check against `email` / `username` and rejection.
- Library wrapper like `password-validator`, `joi.string().pattern(...)`,
  Django's `validate_password()` with `AUTH_PASSWORD_VALIDATORS`
  configured.

## How to investigate (use the tools)

1. **Find the password-hashing call.** Locate `bcrypt.hash`, `argon2.hash`,
   `pbkdf2`, `scrypt`, `crypto.scrypt`, or the project's `security.hash`.

2. **Trace backwards from the hash.** Where does the plaintext come
   from? `req.body.password`? Through a schema? Through a model setter?

3. **Read the model file.** If `User` is a Sequelize/Mongoose/TypeORM
   model and there's a setter or hook on `password`, Read it. Does
   the setter validate before hashing?

4. **Read the validator helpers.** If the handler imports
   `validatePassword`, `passwordPolicy`, `validators.password`, Read
   that module. What does it actually check?

5. **Look at the schema.** If a Zod/Joi/Pydantic/class-validator schema
   parses the request body, does the `password` field have constraints?

If you can trace the input from request to hash without encountering
a length or strength check, flag it.

## True positive criteria

Flag when ALL of the following hold:

1. A password is accepted from request input and hashed for storage.
2. No length minimum (≥ 8), no common-password-deny check, no
   username/email equality check, and no schema constraint enforces
   minimum complexity on the path.

## What to ignore

- Internal admin tools where the actor is a privileged role and the
  password is rotated immediately.
- Service accounts with auto-generated random passwords (no user
  input).
- Test fixtures and seed scripts.
- Paths where the password input is already validated by a global
  middleware you've confirmed.

## Examples

True positives:
```ts
// No length / strength check anywhere on the path
const u = await User.create({
  email: req.body.email,
  password: bcrypt.hashSync(req.body.password, 10),
});
```
```python
# Pydantic without constraints, no validator
class Register(BaseModel):
    email: EmailStr
    password: str
@app.post("/register")
def register(body: Register):
    user.password = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt())
```

False positives to skip:
```ts
// Sequelize setter with explicit checks
User.init({
  password: {
    type: DataTypes.STRING,
    set(plain: string) {
      validatePasswordHasAtLeastTenChar(plain);
      validatePasswordIsNotInTopOneMillionCommonPasswordsList(plain);
      this.setDataValue("password", security.hash(plain));
    },
  },
});

// Zod with length + zxcvbn refinement
const Schema = z.object({
  password: z.string().min(10).refine(p => zxcvbn(p).score >= 3, "too weak"),
});
```
```python
# Django with AUTH_PASSWORD_VALIDATORS configured + validate_password called
from django.contrib.auth.password_validation import validate_password
validate_password(body["password"])
user.set_password(body["password"])
```

Length alone is the bare minimum; reject anything that doesn't even
do `.length >= 8`. Stronger policies (zxcvbn, breach corpus check)
are the goal, but their absence isn't a finding on its own — focus
on outright missing enforcement.
