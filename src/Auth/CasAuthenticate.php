<?php
/**
 * Copyright 2015 Glen Sawyer
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @copyright 2015 Glen Sawyer
 * @license http://www.apache.org/licenses/LICENSE-2.0 Apache License 2.0
 */

namespace CasAuth\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Controller\Component\AuthComponent;
use Cake\Core\Configure;
use Cake\Event\Event;
use Cake\Event\EventDispatcherTrait;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\Routing\Router;
use phpCAS;

class CasAuthenticate extends BaseAuthenticate
{
    use EventDispatcherTrait;

    protected $_defaultConfig = [
        'hostname' => null,
        'port' => 443,
        'uri' => '',
        'debug' => false,
        'start_session' => false,
        'cert_path' => '',
    ];

    public function __construct(ComponentRegistry $registry, $config = [])
    {

        // Set config params using Configure::write or Auth->config
        parent::__construct($registry, (array)Configure::read('CAS'));

        $this->setConfig($config);
        $settings = $this->getConfig();

        // Set debug if specfied in config.
        if (!empty($settings['debug'])) {
            phpCAS::setDebug(LOGS . 'phpcas.log');
        }

        if (!phpCAS::isInitialized()) {
            phpCAS::client(
                CAS_VERSION_2_0,
                $settings['hostname'],
                $settings['port'],
                $settings['uri'],
                $settings['start_session']
            );
        }

        // No server validation for now, during dev.
        if (empty($settings['cert_path'])) {
           phpCAS::setNoCasServerValidation();
        } else {
           phpCAS::setCasServerCACert($settings['cert_path']);
        }

        if (!empty($registry)) {
           $controller = $registry->getController();
           if (!empty($controller)) {
               $this->setEventManager($controller->getEventManager());
           }
        }
    }

    public function authenticate(ServerRequest $request, Response $response)
    {
        phpCAS::handleLogoutRequests(false);
        phpCAS::forceAuthentication();

        $user = array_merge(['username' => phpCAS::getUser()], phpCAS::getAttributes());

        $event = $this->dispatchEvent('CasAuth.authenticate', $user);
        if (!empty($event->result)) {
            $user = $event->result;
        }

        return $user;

    }

    public function getUser(ServerRequest $request)
    {

        if (empty($this->_registry)) {
            return false;
        }

        $controller = $this->_registry->getController();
        if (empty($controller->Auth)) {
            return false;
        }

        if (!phpCAS::isAuthenticated()) {
            phpCAS::forceAuthentication();
        }

        $casUserName = phpCAS::getUser();
        return ['userame' => $casUserName];
    }

    public function logout(Event $event)
    {

        if (phpCAS::isAuthenticated()) {
            $auth = $event->getSubject();
            if ($auth instanceof AuthComponent) {
                $redirectUrl = $auth->getConfig('logoutRedirect');
            }

            if (empty($redirectUrl)) {
                $redirectUrl = '/';
            }
        }

        $logoutUrl = getenv('CAS_LOGOUT_URL');
        if ($logoutUrl == FALSE) {
            throw new Exception("No CAS logout url provided.");
        }
        phpCAS::logout(['url' => $logoutUrl]);

    }

    public function implementedEvents()
    {
        return ['Auth.logout' => 'logout'];
    }
}
