<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Security;
use XD\OIDCProvider\Repository\ClientRepository;

/**
 * OIDC RP-Initiated Logout endpoint (/oauth/logout = the `end_session_endpoint`).
 *
 * A relying party redirects the browser here to end the session (e.g. .NET /
 * Duende does this on sign-out; without this endpoint their handler throws
 * "Cannot redirect to the end session endpoint"). When a valid
 * `post_logout_redirect_uri` is supplied (allowlisted for the client) we redirect
 * back to it echoing `state`.
 *
 * By default this does NOT end this site's own session — logging out of a
 * downstream relying party should leave the primary-site session intact. Set
 * `end_session_logs_out` to true for full SSO single-logout.
 *
 * The id_token_hint is used only to identify the client (its `aud`) so we can
 * pick the right allowlist; the security boundary is the allowlist itself — we
 * never redirect to a URI no configured client registered — so the hint's
 * signature is not verified here. Logging out only ever affects the visitor's
 * own session.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */
class LogoutController extends Controller
{
    use OAuthControllerTrait;

    private static array $allowed_actions = [
        'index',
    ];

    /**
     * Whether hitting the end_session_endpoint also ends THIS site's session
     * (single logout). Default false: logging out of a downstream relying party
     * (e.g. an LMS) should NOT log the user out of this primary site. Only the
     * RP's own logout completes. Set true for full SSO single-logout.
     */
    private static bool $end_session_logs_out = false;

    public function index(HTTPRequest $request): HTTPResponse
    {
        $postLogoutRedirectUri = (string) $request->getVar('post_logout_redirect_uri');
        $state = (string) $request->getVar('state');
        $clientId = $this->resolveClientId($request);

        // Optionally end the IdP session too (single logout). Off by default so a
        // downstream app's logout leaves the primary-site session intact.
        if ($this->config()->get('end_session_logs_out') && Security::getCurrentUser()) {
            Injector::inst()->get(IdentityStore::class)->logOut($request);
        }

        if (
            $postLogoutRedirectUri !== ''
            && ClientRepository::singleton()->isPostLogoutRedirectAllowed($clientId, $postLogoutRedirectUri)
        ) {
            $target = $postLogoutRedirectUri;
            if ($state !== '') {
                $target .= (strpos($target, '?') === false ? '?' : '&') . 'state=' . rawurlencode($state);
            }

            return $this->redirect($target);
        }

        $response = HTTPResponse::create('Logged out.', 200);
        $response->addHeader('Content-Type', 'text/plain; charset=utf-8');

        return $response;
    }

    /** Client id from the explicit `client_id` param, else the id_token_hint `aud`. */
    private function resolveClientId(HTTPRequest $request): ?string
    {
        $clientId = (string) $request->getVar('client_id');
        if ($clientId !== '') {
            return $clientId;
        }

        $hint = (string) $request->getVar('id_token_hint');
        if ($hint === '') {
            return null;
        }

        $parts = explode('.', $hint);
        if (count($parts) < 2) {
            return null;
        }

        $segment = strtr($parts[1], '-_', '+/');
        if (($pad = strlen($segment) % 4) !== 0) {
            $segment .= str_repeat('=', 4 - $pad);
        }

        $payload = json_decode((string) base64_decode($segment), true);
        if (!is_array($payload) || !isset($payload['aud'])) {
            return null;
        }

        $aud = $payload['aud'];
        $aud = is_array($aud) ? (string) ($aud[0] ?? '') : (string) $aud;

        return $aud !== '' ? $aud : null;
    }
}
