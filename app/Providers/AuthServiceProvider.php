<?php

namespace App\Providers;

use App\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use \Firebase\JWT\JWT;
use App\Services\Auth\jwtGuard as Auth;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [];

    /**
     * Register the application's policies.
     *
     * @return void
     */
    public function registerPolicies()
    {
        foreach ($this->policies() as $key => $value) {
            Gate::policy($key, $value);
        }
    }

    /**
     * Get the policies defined on the provider.
     *
     * @return array
     */
    public function policies()
    {
        return $this->policies;
    }


    /**
     * Boot the authentication services for the application.
     *
     * @return void
     */
    public function boot()
    {

        $this->registerPolicies();

        Auth::viaRequest('jwt', function ($request) {
            $publicKey = file_get_contents(storage_path('oauth-public.key'));

            if(!$hasAuthHeader = $request->header('Authorization')?true:false){
                return null;
            }

            preg_match('/Bearer\s((.*)\.(.*)\.(.*))/', $request->header('Authorization'), $jwt);

            try {
                $res                        = JWT::decode($jwt[1], $publicKey, array('RS256'));
                $jwt_user                   = json_decode(json_encode($res->user), true);
                $local_user                 = User::find($jwt_user['id']);
                $jwt_user['local_profile']  = $local_user?$local_user:[];
                $user                       = new User([], $jwt_user);
                return $user;
            } catch (\Exception $e) {
                return null;
            }
        });
    }
}
