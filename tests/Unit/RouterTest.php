<?php

declare(strict_types=1);

namespace gcgov\framework\services\usercrud\tests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use gcgov\framework\services\usercrud\router;
use gcgov\framework\models\environmentConfig;
use gcgov\framework\models\route;

#[CoversClass(router::class)]
final class RouterTest extends TestCase {

	protected function setUp(): void {
		$envConfig = new environmentConfig();
		$envConfig->basePath = 'api';

		$prop = new \ReflectionProperty( \gcgov\framework\config::class, 'environmentConfig' );
		$prop->setValue( null, $envConfig );
	}

	public function testRouterImplementsFrameworkRouterInterface(): void {
		$this->assertContains(
			\gcgov\framework\interfaces\router::class,
			class_implements( router::class ) ?: []
		);
	}

	public function testGetRoutesReturnsFourCrudRoutes(): void {
		$routes = ( new router() )->getRoutes();
		$this->assertCount( 4, $routes );
		foreach ( $routes as $route ) {
			$this->assertInstanceOf( route::class, $route );
		}
	}

	public function testGetAllRouteIsGetAtBasePathUser(): void {
		$route = $this->routes()[0];
		$this->assertSame( 'GET', $route->httpMethod );
		$this->assertSame( '/api/user', $route->route );
		$this->assertSame( 'getAll', $route->method );
		$this->assertTrue( $route->authentication );
		$this->assertSame( [ 'User.Read' ], $route->requiredRoles );
	}

	public function testGetOneRouteIsGetWithIdParameter(): void {
		$route = $this->routes()[1];
		$this->assertSame( 'GET', $route->httpMethod );
		$this->assertSame( '/api/user/{_id}', $route->route );
		$this->assertSame( 'getOne', $route->method );
		$this->assertTrue( $route->authentication );
		$this->assertSame( [ 'User.Read' ], $route->requiredRoles );
	}

	public function testSaveRouteIsPostAndRequiresWritePermission(): void {
		$route = $this->routes()[2];
		$this->assertSame( 'POST', $route->httpMethod );
		$this->assertSame( '/api/user/{_id}', $route->route );
		$this->assertSame( 'save', $route->method );
		$this->assertSame( [ 'User.Read', 'User.Write' ], $route->requiredRoles );
	}

	public function testDeleteRouteIsDeleteAndRequiresWritePermission(): void {
		$route = $this->routes()[3];
		$this->assertSame( 'DELETE', $route->httpMethod );
		$this->assertSame( '/api/user/{_id}', $route->route );
		$this->assertSame( 'delete', $route->method );
		$this->assertSame( [ 'User.Read', 'User.Write' ], $route->requiredRoles );
	}

	public function testAllRoutesTargetUserController(): void {
		$expected = [
			'gcgov\framework\services\usercrud\controllers\user',
			'\gcgov\framework\services\usercrud\controllers\user',
		];
		foreach ( $this->routes() as $route ) {
			$this->assertContains( $route->class, $expected );
		}
	}

	public function testAuthenticationContractReturnsTrue(): void {
		$routeHandler = $this->createStub( \gcgov\framework\models\routeHandler::class );
		$this->assertTrue( ( new router() )->authentication( $routeHandler ) );
	}

	public function testLifecycleHooksAreCallable(): void {
		router::_before();
		router::_after();
		$this->assertTrue( true );
	}

	/** @return list<route> */
	private function routes(): array {
		return ( new router() )->getRoutes();
	}

}
