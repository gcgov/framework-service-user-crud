<?php

declare(strict_types=1);

namespace gcgov\framework\services\usercrud\tests\Unit;

use PHPUnit\Framework\TestCase;
use gcgov\framework\services\usercrud\router;

final class RouterSmokeTest extends TestCase {

	public function testRouterImplementsFrameworkRouterInterface(): void {
		$this->assertContains(
			\gcgov\framework\interfaces\router::class,
			class_implements( router::class ) ?: []
		);
	}

	public function testAuthenticationDelegatesToFramework(): void {
		$routeHandler = $this->createStub( \gcgov\framework\models\routeHandler::class );
		$this->assertTrue( ( new router() )->authentication( $routeHandler ) );
	}

	public function testLifecycleHooksAreCallable(): void {
		router::_before();
		router::_after();
		$this->assertTrue( true );
	}

}
