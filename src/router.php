<?php

namespace gcgov\framework\services\authoauth;

use gcgov\framework\config;
use gcgov\framework\exceptions\routeException;
use gcgov\framework\exceptions\serviceException;
use gcgov\framework\models\route;

class router
	implements
	\gcgov\framework\interfaces\router {

	public function getRoutes(): array {
		return [
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/.well-known/jwks.json', '\gcgov\framework\services\authoauth\controllers\auth', 'jwks', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/.well-known/openid-configuration', '\gcgov\framework\services\authoauth\controllers\auth', 'openid', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/auth/fileToken', '\gcgov\framework\services\authoauth\controllers\auth', 'fileToken', true ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/auth/out', '\gcgov\framework\services\authoauth\controllers\auth', 'out', true ),
			new route( 'POST', config::getEnvironmentConfig()->getBasePath() . '/auth/authorize', '\gcgov\framework\services\authoauth\controllers\auth', 'oauthPostAuthorize', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/auth/authorize', '\gcgov\framework\services\authoauth\controllers\auth', 'oauthGetAuthorize', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/auth/hybridauth/{provider}', '\gcgov\framework\services\authoauth\controllers\auth', 'oauthHybridAuth', false ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/user', '\gcgov\framework\controllers\user', 'getAll', true, [ 'User.Read' ] ),
			new route( 'GET', config::getEnvironmentConfig()->getBasePath() . '/user/{_id}', '\gcgov\framework\controllers\user', 'getOne', true, [ 'User.Read' ] ),
			new route( 'POST', config::getEnvironmentConfig()->getBasePath() . '/user/{_id}', '\gcgov\framework\controllers\user', 'save', true, [ 'User.Read', 'User.Write' ] ),
			new route( 'DELETE', config::getEnvironmentConfig()->getBasePath() . '/user/{_id}', '\gcgov\framework\controllers\user', 'delete', true, [ 'User.Read', 'User.Write' ] )
		];
	}


	public function authentication( \gcgov\framework\models\routeHandler $routeHandler ): bool {
		$accessToken = $_SERVER[ 'HTTP_AUTHORIZATION' ] ?? null;

		if( !isset( $_SERVER[ 'HTTP_AUTHORIZATION' ] ) ) {
			if( !$routeHandler->allowShortLivedUrlTokens ) {
				throw new \gcgov\framework\exceptions\routeException( 'Missing Authorization', 401 );
			}

			if( !isset( $_GET[ 'fileAccessToken' ] ) ) {
				throw new \gcgov\framework\exceptions\routeException( 'Missing Authorization', 401 );
			}
			$accessToken = $_GET[ 'fileAccessToken' ];
		}

		//validate JWT provided in request
		$jwtService = new \gcgov\framework\services\jwtAuth\jwtAuth();
		try {
			$parsedToken = $jwtService->validateAccessToken( $accessToken );

			//token is valid
			$tokenData   = $parsedToken->claims()->get( 'data' );
			$tokenScopes = (array)$parsedToken->claims()->get( 'scope' );

			//parse the authenticated user from the jwt
			$authUser = \gcgov\framework\services\request::getAuthUser();
			$authUser->setFromJwtToken( $tokenData, $tokenScopes );
		}
		catch( serviceException $e ) {
			//JWT uses invalid kid/guid
			throw new \gcgov\framework\exceptions\routeException( $e->getMessage(), 401, $e );
		}
		catch( \Lcobucci\JWT\Encoding\CannotDecodeContent|\Lcobucci\JWT\Token\UnsupportedHeaderFound|\Lcobucci\JWT\Token\InvalidTokenStructure $e ) {
			//JWT did not parse
			throw new routeException( 'Token parsing failed', 401, $e );
		}
		catch( \Lcobucci\JWT\Validation\RequiredConstraintsViolated $e ) {
			//JWT parsed successfully but failed validation
			$violations        = $e->violations();
			$violationMessages = [];
			foreach( $violations as $violation ) {
				$violationMessages[] = $violation->getMessage();
			}
			throw new routeException( 'Token validation failed: ' . implode( ', ', $violationMessages ), 401, $e );
		}

		//verify user roles allow them to access this resource
		if( count( $routeHandler->requiredRoles )>0 ) {
			foreach( $routeHandler->requiredRoles as $requiredRole ) {
				if( !in_array( $requiredRole, $authUser->roles ) ) {
					throw new \gcgov\framework\exceptions\routeException( 'User does not have the permission "' . $requiredRole . '" required to access this content', 403 );
				}
			}
		}

		//user has been authenticated
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
