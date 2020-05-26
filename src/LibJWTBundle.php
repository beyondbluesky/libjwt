<?php

/* 
 * The Creative Commons BY-NC-SA 4.0 License
 * Attribution-NonCommercial-ShareAlike 4.0 International
 * Josep Llauradó Selvas
 * pep@beyondbluesky.com
 * 
 * 
*/

namespace BeyondBlueSky\LibJWT;

use BeyondBlueSky\LibJWT\DependencyInjection\JWTServiceExtension;

use Symfony\Component\HttpKernel\Bundle\Bundle;

class LibJWTBundle extends Bundle
{
    /**
     * Overridden to allow for the custom extension alias.
     *
     * @return KnpUOAuth2ClientExtension
     */
    public function getContainerExtension()
    {
        if (null === $this->extension) {
            return new JWTServiceExtension();
        }

        return $this->extension;
    }
}