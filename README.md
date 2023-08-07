# User CRUD Service

## Service to extend gcgov/framework

### Primary purpose

* Implement standard CRUD routes to manage the user collection. Even if your app doesn't provide a custom user
  model (`\app\models\user`), your auth or database service may provide you with a standard user model that
  implements (`\gcgov\framework\interfaces\auth\user`).

### User Model Standard and Customization

* The class fully qualified domain name returned by `\gcgov\framework\services\request::getUserClassFqdn()` shall be
  used to select the correct user model for purposes of authentication services and the user crud service. The class
  returned by `request::getUserClassFqdn` must implement `\gcgov\framework\interfaces\auth\user`. It will
  return the first class available in this list, in order.
    1. `\app\models\user`
    2. Database provider user model
        * `\gcgov\framework\services\mongodb\models\auth\user`

### Impact to application

* **Router**
    * **User Routes** Adds standard CRUD user controller that will interface with the application's user model.
        * Adds route `/user` - GET all users; Required Roles: `User.Read`
        * Adds route `/user/{id}` - GET one user by id or 'new'; Required Roles: `User.Read`
        * Adds route `/user/{id}` - POST save user; Required Roles: `User.Read`, `User.Write`
        * Adds route `/user/{id}` - DELETE user; Required Roles: `User.Read`, `User.Write`
    * Adds authentication guard
        * All routes in app with authentication=true will be guarded by this guard. The HTTP Authorization header is
          required and it's access token is validated by the jwt service.
        * Provided user routes require authentication and `User.Read`/`User.Write` roles.

## Installation:

* Require using Composer https://packagist.org/packages/gcgov/framework-service-auth-oauth-server
* Add namespace `\gcgov\framework\services\authoauth` to `\app\app->registerFrameworkServiceNamespaces()`

## Implementation
