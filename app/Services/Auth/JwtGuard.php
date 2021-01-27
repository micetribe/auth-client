<?php


namespace App\Services\Auth;


use Illuminate\Auth\GenericUser;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use \Firebase\JWT\JWT;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{

    use GuardHelpers;

    /**
     * @var Request
     */
    private $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        if(!$jwt = $this->getJwt()) {
            return null;
        }

        return $this->decode($jwt);
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if(!$jwt = $this->getJwt()) {
            return false;
        }

        return !is_null($this->decode($jwt))?true:false;
    }

    /**
     * Decode JWT and return user
     *
     * @return mixed|null
     */
    private function decode($jwt)
    {
        $publicKey = file_get_contents(storage_path('oauth-public.key'));

        try {
            $res = JWT::decode($jwt, $publicKey, array('RS256'));
            return $this->user = new GenericUser(json_decode(json_encode($res->user), true));
        } catch (\Exception $e) {
            return null;
        }
    }

    private function hasAuthHeader()
    {
        return $this->request->header('Authorization')?true:false;
    }

    private function getJwt()
    {
        if(!$this->hasAuthHeader()){
            return null;
        }

        preg_match('/Bearer\s((.*)\.(.*)\.(.*))/', $this->request->header('Authorization'), $jwt);

        return $jwt[1]?$jwt[1]:null;
    }
}
