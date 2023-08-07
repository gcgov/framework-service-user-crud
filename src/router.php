<?php

namespace gcgov\framework\services\usercrud;

use gcgov\framework\config;
use gcgov\framework\exceptions\routeException;
use gcgov\framework\exceptions\serviceException;
use gcgov\framework\models\route;

class router
	implements
	\gcgov\framework\interfaces\router {

	public function getRoutes(): array {
		return [
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/user', 'gcgov\framework\services\usercrud\controllers\user', 'getAll', true, [ 'User.Read' ] ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/user/{_id}', '\gcgov\framework\services\usercrud\controllers\user', 'getOne', true, [ 'User.Read' ] ),
			new route( 'POST', config::getEnvironmentConfig()->getBasePath() . '/user/{_id}', '\gcgov\framework\services\usercrud\controllers\user', 'save', true, [ 'User.Read', 'User.Write' ] ),
			new route( 'DELETE', config::getEnvironmentConfig()->getBasePath() . '/user/{_id}', '\gcgov\framework\services\usercrud\controllers\user', 'delete', true, [ 'User.Read', 'User.Write' ] )
		];
	}


	public function authentication( \gcgov\framework\models\routeHandler $routeHandler ): bool {
		//this service does not implement a route guard
		return true;
	}


	/**
	 * Processed after lifecycle is complete with this instance
	 */
	public static function _after(): void {
	}


	/**
	 * Processed prior to __constructor() being called
	 */
	public static function _before(): void {
	}

}
