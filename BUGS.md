# Bug Manifest

## Bug 1: Hardcoded JWT Secret in AuthModule
- **Category:** Security
- **Severity:** Critical
- **File:** apps/api/src/modules/auth/auth.module.ts
- **Line:** ~12
- **Description:** `JwtModule.register()` is called with a hardcoded `secret: 'fx-nx-stack-secret'`. This value is committed to source control and takes precedence over the runtime environment variable configured in `auth.config.ts`. Any JWTs signed with the environment-supplied secret will still validate against the hardcoded one if the module-level secret is picked up first, or vice versa depending on how `JwtService` resolves it. Either way, the secret is now public knowledge via the repo, making every token trivially forgeable by anyone who has read access to the codebase.
- **How to find it:** Search for `JwtModule.register(` and check the arguments. The `register({})` call was replaced with an inline `{ secret: '...' }`. Compare against `auth.config.ts` which correctly reads from environment variables.
- **Fix:** Revert to `JwtModule.register({})` and ensure all JWT signing uses the per-call `secret` option drawn from `ConfigService`, which is already done correctly in `AuthService.getCookieWithJwtAccessToken()` and `getCookieWithJwtRefreshToken()`.

---

## Bug 2: Missing JwtAuthGuard on UsersController
- **Category:** Security
- **Severity:** Critical
- **File:** apps/api/src/modules/users/users.controller.ts
- **Line:** ~23
- **Description:** The `@UseGuards(JwtAuthGuard)` decorator was removed from `UsersController`. All routes in this controller (`POST /users` and `GET /users`) are now publicly accessible without any authentication token. An unauthenticated attacker can enumerate all users or create new user accounts arbitrarily.
- **How to find it:** Review each controller class for the presence of `@UseGuards`. The Swagger `@ApiCookieAuth()` decorator still decorates the class (suggesting intent to protect the route), but there is no corresponding runtime guard enforcing it. Compare against `AuthController` which correctly applies `@UseGuards(JwtAuthGuard)` per method.
- **Fix:** Re-add `@UseGuards(JwtAuthGuard)` at the class level and restore the `JwtAuthGuard` import.

---

## Bug 3: Plaintext Password Logged on Every Authentication Attempt
- **Category:** Security
- **Severity:** Critical
- **File:** apps/api/src/modules/auth/auth.service.ts
- **Line:** ~115
- **Description:** A `this.logger.log(...)` call was added to `getAuthenticatedUser()` that logs both the user's email address and their plaintext password (`password=${plainTextPassword}`) at the `log` level. This means every login attempt writes the user's plaintext password to application logs, which are typically persisted to disk, forwarded to log aggregators, and accessible to anyone with log access — a severe credential exposure.
- **How to find it:** Search for `this.logger.log` within auth and service files. Look for any log statements that reference parameters named `password`, `plainText`, `token`, or similar sensitive values. This one uses template literal interpolation of `plainTextPassword` directly.
- **Fix:** Remove the log statement entirely. If diagnostic logging is needed, log only non-sensitive context such as the email and a timestamp, never the password.

---

## Bug 4: Missing Database Index on uuid Column
- **Category:** Performance
- **Severity:** High
- **File:** apps/api/src/modules/database/base.abstract.entity.ts
- **Line:** ~35
- **Description:** The `@Index({ unique: true })` decorator was removed from the `uuid` column on `BaseAbstractEntity`. Every entity in the application extends this base class, meaning all entities (including `User`) now lack a database index on `uuid`. UUID lookups (which are common — UUIDs are the public-facing identifier used in API responses and the `findOne(uuid)` path in `CrudAbstractService`) now require a full table scan instead of an index seek. This degrades read performance significantly as the table grows.
- **How to find it:** Inspect `BaseAbstractEntity`. The `uuid` column has `@Generated('uuid')` and `@Column()` but no `@Index()`. Compare against the `email` column on `User` which retains `unique: true` inside `@Column()` (which does create an index), and note the asymmetry. Also check TypeORM migration output — no index will be generated for `uuid`.
- **Fix:** Re-add `@Index({ unique: true })` above `@Generated('uuid')` on the `uuid` field, and restore the `Index` import from `typeorm`.

---

## Bug 5: N+1 Query in getUsersWithDetails
- **Category:** Performance
- **Severity:** High
- **File:** apps/api/src/modules/users/users.service.ts
- **Line:** ~87
- **Description:** The `getUsersWithDetails()` method iterates over an array of `userIds` and issues a separate `findOne` database query per id inside a `for...of` loop (sequential `await` in a loop). For N user ids, this executes N+1 queries (one per user) instead of a single batched query. Under load or with large id sets, this causes severe latency and excessive database connection use.
- **How to find it:** Look for `await` inside `for` or `forEach` loops that call repository methods. The pattern `for (const id of ids) { const entity = await repo.findOne(...) }` is the classic N+1 symptom in TypeORM services.
- **Fix:** Replace the loop with a single batched query: `return this.usersRepository.find({ where: { id: In(userIds) } })` using TypeORM's `In` operator, importing `In` from `typeorm`.

---

## Bug 6: Class-Validator Decorators Stripped from RegisterUserDto
- **Category:** Reliability
- **Severity:** High
- **File:** apps/api/src/modules/auth/dto/register-user.dto.ts
- **Line:** ~1
- **Description:** The `@IsEmail()` decorator was removed from the `email` field and `@MinLength(8)` was removed from the `password` field. The global `ValidationPipe` is configured with `whitelist: true` and `forbidNonWhitelisted: true`, but validation of field constraints only applies to decorators that are present. Without `@IsEmail()`, any string (including malformed values like `"notanemail"`) passes as a valid email. Without `@MinLength(8)`, a one-character password is accepted. Both weaken data integrity and security guarantees silently — the endpoint returns 201 with no error.
- **How to find it:** Compare `RegisterUserDto` against `ChangePasswordDto` (which still has `@MinLength(8)`) or against the Git history. Note that `IsEmail` and `MinLength` are no longer imported, which is a signal that validators were removed rather than just reorganized.
- **Fix:** Restore `@IsEmail()` on `email` and `@MinLength(8)` on `password`, and restore the missing imports.

---

## Bug 7: Missing refreshTokenHash Null Check Causes Runtime Crash on Token Refresh
- **Category:** Reliability
- **Severity:** High
- **File:** apps/api/src/modules/auth/strategies/jwt-refresh-token.strategy.ts
- **Line:** ~44
- **Description:** The guard condition `!user.refreshTokenHash` was removed from the null check in `JwtRefreshTokenStrategy.validate()`. Previously the code threw `UnauthorizedException` if the user had no stored refresh token hash (e.g. after sign-out). Now it passes `null` (typed as `string` via a `as string` cast) to `this.authService.verifyHash()`, which calls `argon2.verify(null, refreshToken)`. `argon2.verify` expects a non-null hash string and will throw an unhandled error, causing the refresh endpoint to return a 500 Internal Server Error instead of a clean 401 Unauthorized. This both degrades reliability and leaks internal error details to the client.
- **How to find it:** Read `jwt-refresh-token.strategy.ts` validate method. Notice the `if (!user)` check no longer includes `|| !user.refreshTokenHash`. Also notice `user.refreshTokenHash as string` — the type cast is a code smell indicating the compiler was complaining about a potential null, which was suppressed rather than fixed.
- **Fix:** Restore the combined guard: `if (!user || !user.refreshTokenHash) { throw new UnauthorizedException() }` and remove the `as string` cast.

---

## Bug 8: Empty Catch Block Silently Swallows JWT Verification Errors
- **Category:** Reliability
- **Severity:** Medium
- **File:** apps/api/src/modules/auth/auth.service.ts
- **Line:** ~141
- **Description:** `getUserByAuthenticationToken()` now wraps the entire body in a try/catch with an empty catch block, which silently returns `undefined` on any error. This is called in contexts where a tampered, expired, or malformed token should produce a clear `UnauthorizedException`. Instead, any exception (invalid signature, expired token, network hiccup during user lookup) causes the method to return `undefined` silently. Callers that don't defensively check for `undefined` may proceed as if no user was found, potentially allowing bypass logic or causing confusing downstream NullReferenceErrors with no useful log output.
- **How to find it:** Search for `catch` blocks with no body (`catch { }` or `catch (e) {}`). This is a known code smell. `jwtService.verify()` is documented to throw on invalid tokens — catching and suppressing that throw means the error is never surfaced to the caller or logged.
- **Fix:** Remove the try/catch entirely (the original code had none), or at minimum rethrow after logging: `catch (error) { this.logger.error(...); throw new UnauthorizedException() }`.

---

## Bug 9: TypeScript strict Mode Disabled Across Entire Monorepo
- **Category:** Developer Tooling
- **Severity:** Medium
- **File:** tsconfig.base.json
- **Line:** ~14
- **Description:** `"strict": false` was added to the root `tsconfig.base.json`, which is extended by all TypeScript projects in the monorepo (API, UI, libs). This disables a bundle of compiler checks including `strictNullChecks`, `noImplicitAny`, `strictFunctionTypes`, and `strictPropertyInitialization`. Code that was previously valid under strict mode may still compile, but new code written without null checks or with implicit `any` types will now compile without errors, silently introducing whole classes of runtime bugs. This is especially dangerous in a codebase that relies on type-safe TypeORM entities and NestJS DI.
- **How to find it:** Check `tsconfig.base.json` for `"strict": false`. Compare against the `tsconfig.app.json` and `tsconfig.spec.json` files — none of them re-enable strict mode, so `false` cascades everywhere. A dead giveaway is that `"strict"` is present but set to `false` rather than being absent (the default is `false`, so setting it explicitly to `false` typically means someone toggled it off).
- **Fix:** Remove `"strict": false` from `tsconfig.base.json`. Ideally replace it with `"strict": true` to enforce strict mode across the monorepo, then resolve any newly surfaced type errors.
