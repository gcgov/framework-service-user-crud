<?php

declare(strict_types=1);

namespace app\models;

/**
 * Stub user model used by the user-crud tests. The user controller looks up
 * the user model class via gcgov\framework\services\request::getUserClassFqdn,
 * which returns \app\models\user when it exists. Each test populates the
 * static $records array to drive the controller's behaviour.
 */
class user {

	/** @var array<string, self> */
	public static array $records = [];

	/** @var \Exception|null */
	public static ?\Exception $nextException = null;

	/** @var int */
	public static int $deleteAffectedCount = 1;

	public string $_id = '';
	public string $name = '';

	public static function reset(): void {
		self::$records = [];
		self::$nextException = null;
		self::$deleteAffectedCount = 1;
	}

	/**
	 * @param  int  $limit
	 * @param  int  $page
	 * @param  array<string, mixed>  $filter
	 * @param  array<string, mixed>  $options
	 */
	public static function getPagedResponse( int $limit, int $page, array $filter, array $options ): FakeDbGetResult {
		self::throwIfQueued();
		$result = new FakeDbGetResult();
		$result->setData( array_values( self::$records ) );
		$result->setLimit( $limit );
		$result->setPage( $page );
		$result->setTotalDocumentCount( count( self::$records ) );
		return $result;
	}

	public static function getOne( string $_id ): self {
		self::throwIfQueued();
		if ( !isset( self::$records[ $_id ] ) ) {
			throw new \gcgov\framework\exceptions\modelException( 'not found', 404 );
		}
		return self::$records[ $_id ];
	}

	public static function save( self $user ): self {
		self::throwIfQueued();
		self::$records[ $user->_id ] = $user;
		return $user;
	}

	public static function delete( string $_id ): FakeDeleteResult {
		self::throwIfQueued();
		$count = self::$deleteAffectedCount;
		if ( isset( self::$records[ $_id ] ) ) {
			unset( self::$records[ $_id ] );
		}
		return new FakeDeleteResult( $count );
	}

	public static function jsonDeserialize( string $json ): self {
		$data = json_decode( $json, true ) ?: [];
		$instance = new self();
		$instance->_id = (string) ( $data[ '_id' ] ?? '' );
		$instance->name = (string) ( $data[ 'name' ] ?? '' );
		return $instance;
	}

	private static function throwIfQueued(): void {
		if ( self::$nextException !== null ) {
			$e = self::$nextException;
			self::$nextException = null;
			throw $e;
		}
	}

}

class FakeDeleteResult {
	public function __construct( private int $deletedCount ) {}
	public function getDeletedCount(): int {
		return $this->deletedCount;
	}
}

class FakeDbGetResult implements \gcgov\framework\interfaces\dbGetResult {
	/** @var array<int, mixed> */
	private array $data = [];
	private int $limit = 10;
	private int $page = 1;
	private int $totalDocumentCount = 0;

	public function setData( array $data ): void { $this->data = $data; }
	public function setLimit( int $limit ): void { $this->limit = max( 1, $limit ); }
	public function setPage( int $page ): void { $this->page = max( 1, $page ); }
	public function getData(): array { return $this->data; }
	public function getLimit(): int { return $this->limit; }
	public function getSkip(): int { return ( $this->page - 1 ) * $this->limit; }
	public function getCount(): int { return count( $this->data ); }
	public function getPage(): int { return $this->page; }
	public function getTotalDocumentCount(): int { return $this->totalDocumentCount; }
	public function setTotalDocumentCount( int $totalDocumentCount ): void { $this->totalDocumentCount = $totalDocumentCount; }
	public function getTotalPageCount(): int {
		return (int) ceil( $this->totalDocumentCount / $this->limit );
	}
}
