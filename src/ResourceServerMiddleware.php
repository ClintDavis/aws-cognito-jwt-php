<?php
/**
 * @author      Clint Davis <os-dev@clint.davis.to>
 * @copyright   Copyright (c) Clint Davis
 * @license     http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 *
 * @link        https://github.com/ClintDavis/aws-cognito-jwt-php
 */

namespace ClintDavis\CognitoJwt;


use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ClintDavis\CognitoJwt;

class ResourceServerMiddleware
{
    /**
     * @var boolean $validate
     *  Default is to validate, but save CPU cylces if behind AWS API Gateway.
     */
    private $validate;

    /**
     * @var array $customJson
     *  If have custom attribute that contains json, provide a base64 decode and json decode
     */
    private $customJson;

    /**
     * @param ResourceServer $server
     */
    public function __construct($customJson = null)
    {
        $this->customJson = $customJson;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @param callable               $next
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {

      $jwt = $request->getHeader('Authorization')[0];

      // Explode and validate the jwt for corect format
    	$tks = explode('.', $jwt);
    	list($headb64, $bodyb64, $cryptob64) = $tks;
    	$payload = base64_decode($bodyb64);

      $claims = json_decode($payload);

      // Provide b64 decoder and json to object mapping.
      if (isset($customJson)){
        foreach($customJson as $item) {

          if (isset($claims->{$item})) $claims->{str_replace(':','',$item)} = json_decode(base64_decode($claims->{$item}));
        }
      }

      // map claims onto request
      $request = $request->withAttribute('claims', $claims);
      $response = $next($request, $response);
      return $response;
    }
}
