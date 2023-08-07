<?php

namespace gcgov\framework\services\authoauth\models;

/**
 * @OA\Schema()
 */
class stdAuthResponse extends \andrewsauder\jsonDeserialize\jsonDeserialize {

	/** @OA\Property() */
	public string $token_type = 'Bearer';

	/** @OA\Property() */
	public int $expires_in = 0;

	/** @OA\Property() */
	public string $access_token = '';

	/** @OA\Property() */
	public string $refresh_token = '';


	public function __construct( \Lcobucci\JWT\Token\Plain $accessToken, \Lcobucci\JWT\Token\Plain $refreshToken, string $tokenType = 'Bearer' ) {
		$now                 = new \DateTimeImmutable();
		$this->token_type    = $tokenType;
		$this->expires_in    = $accessToken->claims()->get( 'exp' )->getTimestamp() - $now->getTimestamp();
		$this->access_token  = $accessToken->toString();
		$this->refresh_token = $refreshToken->toString();
	}

}
