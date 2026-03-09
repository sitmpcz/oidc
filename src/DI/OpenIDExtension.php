<?php

namespace Sitmpcz\oidc\DI;

use Sitmpcz\oidc\Security\OpenIDClientService;
use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;
use Nette\Schema\Schema;

final class OpenIDExtension extends CompilerExtension
{
    public function getConfigSchema(): Schema
    {
        return Expect::structure([
            'issuerUrl' => Expect::string()->required()->dynamic(),
            'clientId' => Expect::string()->required()->dynamic(),
            'clientSecret' => Expect::string()->nullable()->dynamic(),
            'redirectUri' => Expect::string()->nullable()->dynamic(),
            'postLogoutRedirectUri' => Expect::string()->nullable()->dynamic(),
            'backchannelLogoutUri' => Expect::string()->nullable()->dynamic(),
            'scopes' => Expect::listOf('string')->default(['openid', 'profile', 'email'])->mergeDefaults(false),
        ]);
    }

    public function loadConfiguration(): void
    {
        $builder = $this->getContainerBuilder();
        $config = $this->config;

        $builder->addDefinition($this->prefix('client'))
            ->setFactory(OpenIDClientService::class, [
                $config->issuerUrl,
                $config->clientId,
                $config->clientSecret,
                $config->redirectUri,
                $config->scopes,
                'netteRequest' => '@Nette\Http\Request',
                'session' => '@Nette\Http\Session',
                'postLogoutRedirectUri' => $config->postLogoutRedirectUri,
                'backchannelLogoutUri' => $config->backchannelLogoutUri,
            ]);
    }
}