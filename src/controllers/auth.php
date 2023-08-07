<?php

namespace gcgov\framework\services\authoauth\controllers;

use gcgov\framework\config;
use gcgov\framework\exceptions\controllerException;
use gcgov\framework\exceptions\modelException;
use gcgov\framework\interfaces\controller;
use gcgov\framework\models\controllerDataResponse;
use gcgov\framework\services\authoauth\models\stdAuthResponse;
use gcgov\framework\services\formatting;
use gcgov\framework\services\log;

/**
 * @OA\Tag(
 *     name="Auth",
 *     description="Standard auth access token/refresh response"
 * )
 */
class auth
	implements
	controller {

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


	public function __construct() {
	}


	/**
	 * @OA\Get(
	 *     path="/.well-known/jwks.json",
	 *     tags={"Auth"},
	 *     description="Oauth jwks.json"
	 * )
	 * @return \gcgov\framework\models\controllerDataResponse
	 */
	public function jwks(): controllerDataResponse {
		$jwtService = new \gcgov\framework\services\jwtAuth\jwtAuth();

		$data = [
			'keys' => $jwtService->getJwksKeys()
		];

		//custom result for /.well-known/jwks.json
		return new controllerDataResponse( $data );
	}


	/**
	 * @OA\Get(
	 *     path="/.well-known/openid-configuration",
	 *     tags={"Auth"},
	 *     description="Oauth openid-configuration"
	 * )
	 * @return \gcgov\framework\models\controllerDataResponse
	 */
	public function openId(): controllerDataResponse {
		$envConfig = config::getEnvironmentConfig();

		$data = [
			"issuer"                                => $envConfig->getBaseUrl(),
			"authorization_endpoint"                => $envConfig->getBaseUrl() . "/auth/authorize",
			"token_endpoint"                        => $envConfig->getBaseUrl() . "/auth/authorize",
			//"userinfo_endpoint"                     => "https://example.com/userinfo",
			"jwks_uri"                              => $envConfig->getBaseUrl() . "/.well-known/jwks.json",
			"end_session_endpoint"                  => $envConfig->getBaseUrl() . "/auth/out",
			"scopes_supported"                      => [
				"login"
			],
			"response_types_supported"              => [
				"code",
				"token"
			],
			"token_endpoint_auth_methods_supported" => [
				"client_secret_post",
				"private_key_jwt",
			],

		];

		//custom result for /.well-known/jwks.json
		return new controllerDataResponse( $data );
	}


	/**
	 * @OA\Get(
	 *     path="/auth/fileToken",
	 *     tags={"Auth"},
	 *     description="Use your app access token to get a very short lived access token that can be used as a URL parameter on specific routes that allow it"
	 * )
	 *
	 * @return \gcgov\framework\models\controllerDataResponse
	 */
	public function fileToken(): controllerDataResponse {
		$authUser = \gcgov\framework\services\request::getAuthUser();

		//generate our custom jwt and return it to the user
		$jwtService  = new \gcgov\framework\services\jwtAuth\jwtAuth();
		$accessToken = $jwtService->createAccessToken( $authUser, new \DateInterval( 'PT5S' ) );

		//return data
		$data = [
			'accessToken' => $accessToken->toString()
		];

		return new controllerDataResponse( $data );
	}


	/**
	 * @OA\Get(
	 *     path="/auth/authorize",
	 *     tags={"Auth"},
	 *     description="Direct access by end user - will send through to selected third party Oauth provider",
	 *     @OA\Parameter(
	 *         name="response_type",
	 *         in="query",
	 *         description="Only supported value is 'code'",
	 *         required=true,
	 *         @OA\Schema(type="string")
	 *     ),
	 *     @OA\Parameter(
	 *         name="client_id",
	 *         in="query",
	 *         description="Must match app config guid",
	 *         required=true,
	 *         @OA\Schema(type="string")
	 *     ),
	 *     @OA\Parameter(
	 *         name="scope",
	 *         in="query",
	 *         description="Must be oauth provider name string (ex. microsoft)",
	 *         required=true,
	 *         @OA\Schema(type="string")
	 *     ),
	 *     @OA\Response(
	 *      response="200",
	 *      description="Successfully fetched",
	 *      @OA\JsonContent(
	 *          type="array",
	 *          @OA\Items(ref="#/components/schemas/stdAuthResponse")
	 *      )
	 *    )
	 * )
	 *
	 * @return \gcgov\framework\models\controllerDataResponse
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	public function oauthGetAuthorize(): controllerDataResponse {
		if( empty( $_GET[ 'response_type' ] ) || $_GET[ 'response_type' ]!='code' ) {
			throw new controllerException( 'Invalid response type', 401 );
		}
		if( empty( $_GET[ 'client_id' ] ) || $_GET[ 'client_id' ]!=config::getAppConfig()->app->guid ) {
			throw new controllerException( 'Invalid client id', 401 );
		}
		if( empty( $_GET[ 'scope' ] ) ) {
			throw new controllerException( 'Invalid scope', 401 );
		}

		if( session_status()!=PHP_SESSION_ACTIVE ) {
			session_start();
		}
		unset( $_SESSION[ 'auth_state' ] );
		if( !empty( $_GET[ 'state' ] ) ) {
			$_SESSION[ 'auth_state' ] = urldecode( $_GET[ 'state' ] );
		}

		$this->oauthHybridAuth( $_GET[ 'scope' ] );

		return new controllerDataResponse();
	}


	/**
	 * @OA\Post(
	 *     path="/auth/authorize",
	 *     tags={"Auth"},
	 *     description="Handler for third party oauth provider (authorization_code), exchange refresh tokens (refresh_token), and exchange username/password (password)",
	 *     @OA\RequestBody(
	 *          @OA\MediaType(
	 *              mediaType="multipart/form-data",
	 *              encoding={}
	 *              @OA\Schema(
	 *                  type="object",
	 *                  @OA\Property(
	 *                      property="grant_type",
	 *                      description="action to perform"
	 *                      @OA\Schema(type="string", enum={"password", "refresh_token", "authorization_code"})
	 *                  ),
	 *                  @OA\Property(
	 *                      property="client_id",
	 *                      description="must match app config guid"
	 *                      @OA\Schema(type="string")
	 *                  ),
	 *                  @OA\Property(
	 *                      property="scope",
	 *                      description="Required if grant_type=password; Must be 'login'"
	 *                      @OA\Schema(type="string")
	 *                  ),
	 *                  @OA\Property(
	 *                      property="username",
	 *                      description="Required if grant_type=password"
	 *                      @OA\Schema(type="string")
	 *                  ),
	 *                  @OA\Property(
	 *                      property="password",
	 *                      description="Required if grant_type=password"
	 *                      @OA\Schema(type="string")
	 *                  )
	 *              )
	 *          )
	 *     ),
	 *     @OA\Response(
	 *      response="200",
	 *      description="Successfully fetched",
	 *      @OA\JsonContent(
	 *          type="array",
	 *          @OA\Items(ref="#/components/schemas/stdAuthResponse")
	 *      )
	 *    )
	 * )
	 *
	 * @return \gcgov\framework\models\controllerDataResponse
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	public function oauthPostAuthorize(): controllerDataResponse {
		$postData = \gcgov\framework\services\request::getPostData();

		if( empty( $postData[ 'grant_type' ] ) ) {
			throw new controllerException( 'Invalid grant type', 401 );
		}
		if( empty( $postData[ 'client_id' ] ) || $postData[ 'client_id' ]!=config::getAppConfig()->app->guid ) {
			throw new controllerException( 'Invalid client id', 401 );
		}

		//route
		if( $postData[ 'grant_type' ]=='password' && config::getAppConfig()->settings->enablePasswordAuthRoutes ) {
			return new controllerDataResponse( $this->password() );
		}
		elseif( $postData[ 'grant_type' ]=='refresh_token' ) {
			return new controllerDataResponse( $this->refresh_token() );
		}
		elseif( $postData[ 'grant_type' ]=='authorization_code' ) {
			return new controllerDataResponse( $this->authorization_code() );
		}

		throw new controllerException( 'Invalid grant type', 401 );
	}


	/**
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	private function password(): stdAuthResponse {
		$postData = \gcgov\framework\services\request::getPostData();

		if( empty( $postData[ 'scope' ] ) || $postData[ 'scope' ]!='login' ) {
			throw new controllerException( 'Invalid scope', 401 );
		}
		elseif( empty( $postData[ 'username' ] ) ) {
			throw new controllerException( 'Username required', 401 );
		}
		elseif( empty( $postData[ 'password' ] ) ) {
			throw new controllerException( 'Password required', 401 );
		}

		//authenticate user with citizen connect service

		try {
			$userClassName = \gcgov\framework\services\request::getUserClassFqdn();
			$user          = $userClassName::verifyUsernamePassword( $postData[ 'username' ], $postData[ 'password' ] );
		}
		catch( modelException $e ) {
			throw new controllerException( 'Incorrect username or password', 401, $e );
		}

		//create token for good user
		$authUser = \gcgov\framework\services\request::getAuthUser();
		$authUser->setFromUser( $user );

		try {
			$jwtService  = new \gcgov\framework\services\jwtAuth\jwtAuth();
			$accessToken = $jwtService->createAccessToken( $authUser );

			try {
				$refreshToken = $jwtService->createRefreshToken( $authUser );
			}
			catch( modelException $e ) {
				throw new controllerException( 'Server failed to create refresh token', 500, $e );
			}

			return new stdAuthResponse( $accessToken, $refreshToken );
		}
		catch( \Exception $e ) {
			throw new controllerException( $e->getCode(), $e->getMessage(), $e );
		}
	}


	/**
	 * @OA\Get(
	 *     path="/auth/out",
	 *     tags={"Auth"},
	 *     description="Sign out",
	 *     @OA\Response(
	 *      response="201",
	 *      description="Successfully fetched",
	 *    )
	 * )
	 *
	 * @return \gcgov\framework\models\controllerDataResponse
	 */
	public function out(): controllerDataResponse {
		//unset the session variables
		if( isset( $_SESSION ) && is_array( $_SESSION ) ) {
			foreach( $_SESSION as $key => $value ) {
				unset( $_SESSION[ $key ] );
			}
		}

		//delete the session cookie
		$params = session_get_cookie_params();
		setcookie( session_name(),
		           '',
		           time() - 42000,
		           $params[ "path" ],
		           $params[ "domain" ],
		           $params[ "secure" ],
		           $params[ "httponly" ] );

		//destroy the session
		if( session_status()==PHP_SESSION_ACTIVE ) {
			session_destroy();
		}

		//delete all other cookies
		$past = time() - 3600;
		foreach( $_COOKIE as $key => $value ) {
			setcookie( $key, $value, $past, '/' );
		}

		//TODO: burn refresh token

		return new controllerDataResponse( [] );
	}


	/**
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	private function refresh_token(): stdAuthResponse {
		$postData = \gcgov\framework\services\request::getPostData();

		if( empty( $postData[ 'refresh_token' ] ) ) {
			throw new controllerException( 'Invalid refresh token', 401 );
		}

		try {
			\gcgov\framework\services\mongodb\models\auth\userRefreshToken::removeOutdatedRefreshTokens();
		}
		catch( modelException $e ) {
			throw new controllerException( 'Failed to remove outdated refresh token', 500 );
		}

		$jwtValidationService = new \gcgov\framework\services\jwtAuth\jwtAuth();

		try {
			$userId = $jwtValidationService->validateRefreshToken( $postData[ 'refresh_token' ] );
		}
		catch( \Exception $e ) {
			throw new controllerException( $e->getMessage(), 401, $e );
		}

		//invalidate the existing token because we will provide a new one with the response
		try {
			$jwtValidationService->deleteRefreshToken( $postData[ 'refresh_token' ] );
		}
		catch( modelException $e ) {
			throw new controllerException( 'Failed to remove existing refresh token', 500 );
		}

		try {
			$userClassName = \gcgov\framework\services\request::getUserClassFqdn();
			/** @var \gcgov\framework\services\mongodb\models\auth\user $user */
			$user = $userClassName::getOne( $userId );
		}
		catch( modelException $e ) {
			throw new controllerException( 'Refresh token corrupted', 401 );
		}

		//create token for good user
		$authUser = \gcgov\framework\services\request::getAuthUser();
		$authUser->setFromUser( $user );

		$jwtService  = new \gcgov\framework\services\jwtAuth\jwtAuth();
		$accessToken = $jwtService->createAccessToken( $authUser );
		try {
			$refreshToken = $jwtService->createRefreshToken( $authUser );
		}
		catch( modelException $e ) {
			throw new controllerException( 'Failed to create new refresh token', 500 );
		}

		return new stdAuthResponse( $accessToken, $refreshToken );

	}


	/**
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	private function authorization_code(): stdAuthResponse {
		$postData = \gcgov\framework\services\request::getPostData();

		if( empty( $postData[ 'code' ] ) ) {
			throw new controllerException( 'Invalid code', 401 );
		}

		//lookup auth code
		try {
			/** @var \gcgov\framework\services\mongodb\models\auth\userAuthorizationCode $userAuthorizationCode */
			$userAuthorizationCode = \gcgov\framework\services\mongodb\models\auth\userAuthorizationCode::getOne( $postData[ 'code' ] );
		}
		catch( modelException $e ) {
			throw new controllerException( 'Invalid code', 401 );
		}

		try {
			$userClassName = \gcgov\framework\services\request::getUserClassFqdn();
			/** @var \gcgov\framework\services\mongodb\models\auth\user $user */
			$user = $userClassName::getOne( $userAuthorizationCode->userId );
		}
		catch( modelException $e ) {
			throw new controllerException( 'Authorization code corrupted', 401 );
		}

		//create token for good user
		$authUser = \gcgov\framework\services\request::getAuthUser();
		$authUser->setFromUser( $user );

		$jwtService  = new \gcgov\framework\services\jwtAuth\jwtAuth();
		$accessToken = $jwtService->createAccessToken( $authUser );
		try {
			$refreshToken = $jwtService->createRefreshToken( $authUser );
		}
		catch( modelException $e ) {
			throw new controllerException( $e->getMessage(), 500, $e );
		}

		return new stdAuthResponse( $accessToken, $refreshToken );
	}


	/**
	 * @throws \gcgov\framework\exceptions\controllerException
	 */
	public function oauthHybridAuth( string $provider = '' ): void {
		$provider = strtolower( $provider );

		if( $provider=='google' ) {
			$provider = "Google";
		}
		elseif( $provider=='facebook' ) {
			$provider = "Facebook";
		}
		elseif( $provider=='microsoft' || $provider=='microsoftgraph' ) {
			$provider = "MicrosoftGraph";

			if( empty( config::getEnvironmentConfig()->microsoft->clientId ) ) {
				throw new controllerException( 'Microsoft client id has not been defined in the app config file. /app/config/environment.json > microsoft.clientId', 400 );
			}
			if( empty( config::getEnvironmentConfig()->microsoft->clientSecret ) ) {
				throw new controllerException( 'Microsoft client secret has not been defined in the app config file. /app/config/environment.json > microsoft.clientSecret', 400 );
			}
			if( empty( config::getEnvironmentConfig()->microsoft->tenant ) ) {
				throw new controllerException( 'Microsoft tenant has not been defined in the app config file. /app/config/environment.json > microsoft.tenant', 400 );
			}

		}

		if( empty( $provider ) ) {
			throw new controllerException( 'We do not currently support logging in with the service you provided', 400 );
		}

		$config = [
			//Location where to redirect users once they authenticate with a provider
			'callback'  => config::getEnvironmentConfig()->getBaseUrl() . '/auth/hybridauth/' . $provider,

			//Providers specifics
			'providers' => [
				'Google'         => [
					'enabled' => false,
					'keys'    => [
						'id'     => '',
						'secret' => ''
					]
				],
				'Facebook'       => [
					'enabled' => false,
					'keys'    => [
						'id'     => '',
						'secret' => ''
					]
				],
				'MicrosoftGraph' => [
					'enabled' => true,
					'keys'    => [
						'id'     => config::getEnvironmentConfig()->microsoft->clientId,
						'secret' => config::getEnvironmentConfig()->microsoft->clientSecret
					],
					'tenant'  => config::getEnvironmentConfig()->microsoft->tenant,
					//					'endpoints' => [
					//						'api_base_url' => 'https://login.microsoftonline.com/89535794-b398-47e9-9a76-1805684761e6/v2.0',
					//						'authorize_url' => 'https://login.microsoftonline.com/'.config::getEnvironmentConfig()->microsoft->tenant.'/oauth2/v2.0/authorize',
					//						'access_token_url' => 'https://login.microsoftonline.com/'.config::getEnvironmentConfig()->microsoft->tenant.'/oauth2/v2.0/token',
					//					],
					'scope'   => 'openid offline_access profile email'
				],
			]
		];

		try {
			//Feed configuration array to Hybridauth
			$hybridauth = new \Hybridauth\Hybridauth( $config );

			//Then we can proceed and sign in with Twitter as an example. If you want to use a diffirent provider,
			//simply replace 'Twitter' with 'Google' or 'Facebook'.

			//Attempt to authenticate users with a provider by name
			$adapter = $hybridauth->authenticate( $provider );

			//Returns a boolean of whether the user is connected with Twitter
			$isConnected = $adapter->isConnected();

			//Retrieve the user's profile
			$oauthProfile = $adapter->getUserProfile();

			//Disconnect the adapter
			$adapter->disconnect();
		}
		catch( \Exception $e ) {
			error_log( $e );
			$message = $e->getMessage();
			switch( $e->getCode() ) {
				case 0 :
					$message = "Unspecified error.";
					break;
				case 1 :
					$message = "Hybridauth configuration error.";
					break;
				case 2 :
					$message = "Provider not properly configured.";
					break;
				case 3 :
					$message = "Unknown or disabled provider.";
					break;
				case 4 :
					$message = "Missing provider application credentials.";
					break;
				case 5 :
					$message = "The user has canceled the authentication or the provider refused the connection.";
					break;
				case 6 :
					$message = "User profile request failed. Most likely the user is not connected to the provider and he should authenticate again.";
					break;
				case 7 :
					$message = "User not connected to the provider.";
					break;
				case 8 :
					$message = "Provider does not support this feature.";
					break;
			}

			header( 'Location: ' . config::getEnvironmentConfig()->redirectAfterLoginUrl . '?errorMessage=' . urlencode( $message ) );
			exit;
		}

		if( empty( $oauthProfile->email ) ) {
			throw new controllerException( $provider . ' did not provide us with your email address. That is a requirement to sign in.', 401 );
		}

		try {
			$userClassName = \gcgov\framework\services\request::getUserClassFqdn();
			/** @var \gcgov\framework\interfaces\auth\user $user */
			$user = $userClassName::getFromOauth(
				email:         $oauthProfile->email,
				oauthId:       $oauthProfile->identifier,
				oauthProvider: $provider,
				firstName:     $oauthProfile->firstName,
				lastName:      $oauthProfile->lastName,
				addIfNotExisting: false);
		}
		catch( modelException $e ) {
			header( 'Location: ' . config::getEnvironmentConfig()->redirectAfterLoginUrl . '?errorMessage=' . urlencode( $e->getMessage() ) );
			exit;
		}

		try {
			$authorizationCode = new \gcgov\framework\services\mongodb\models\auth\userAuthorizationCode( $user->_id, new \DateInterval( 'PT5M' ) );
			\gcgov\framework\services\mongodb\models\auth\userAuthorizationCode::save( $authorizationCode );
		}
		catch( modelException $e ) {
			throw new controllerException( $provider . 'Server failed to generate an access code.', 500, $e );
		}

		$appendState = '';
		if( !empty( $_SESSION[ 'auth_state' ] ) ) {
			$appendState = '&state=' . $_SESSION[ 'auth_state' ];
		}

		if( session_status()==PHP_SESSION_ACTIVE ) {
			session_destroy();
		}

		header( 'Location: ' . config::getEnvironmentConfig()->redirectAfterLoginUrl . '?code=' . urlencode( (string)$authorizationCode->_id ) . $appendState );
		exit;
	}


	public function createExternalAppToken( string $appName, \DateInterval $tokenExpiration, \MongoDB\BSON\ObjectId $_id, string $username, string $email, string $name, array $roles = [], string $password = '' ): controllerDataResponse {
		$userClassName = \gcgov\framework\services\request::getUserClassFqdn();

		if( $password=='' ) {
			$password = uniqid();
		}

		$user           = new $userClassName();
		$user->_id      = $_id;
		$user->username = $username;
		$user->email    = $email;
		$user->name     = $name;
		$user->password = $password;
		$user->roles    = $roles;
		$user::save( $user );

		$authUser = \gcgov\framework\services\request::getAuthUser();
		$authUser->setFromUser( $user );

		$jwt   = new \gcgov\framework\services\jwtAuth\jwtAuth();
		$token = $jwt->createAccessToken( $authUser, $tokenExpiration );

		if( !file_exists( config::getRootDir() . '/externalAppTokens/' ) ) {
			$created = mkdir( config::getRootDir() . '/externalAppTokens/', 777, true );
			if( !$created ) {
				log::warning( 'auth', 'Directory "' . config::getRootDir() . '/externalAppTokens/" does not exist and could not be created automatically. Create directory to continue.' );
				throw new controllerException( 'Cannot create token because externalAppTokens directory does not exist' );
			}
		}

		$tokenFilePath = config::getRootDir() . '/externalAppTokens/' . formatting::fileName( $appName ) . '.txt';

		file_put_contents( $tokenFilePath, $token->toString() );

		return new controllerDataResponse( $tokenFilePath );
	}


}
