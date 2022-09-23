<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use App\Models\User;
use Validator;


class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Email and Password did not match or Account not found'], 401);
        }

        if (is_null(User::where('email', $request->email)->first(['email_verified_at'])->email_verified_at)) {
            return response()->json(['error' => 'Account not yet verified'], 403);
        }

        // if (is_null(User::where('email', $request->email)->first(['hidden_at'])->hidden_at)) {
        //     return response()->json(['error' => 'Account does not exist'], 406);
        // }

        return $this->createNewToken($token);
    }

    /**
     * Delete account.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function deleteAccount(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6|required_with:cpassword|same:cpassword',
            'cpassword' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Email and Password did not match'], 401);
        }

        if (! auth()->user()) {
            return response()->json(['error' => 'Login first'], 403);
        }

        $id = auth()->user()->id;

        if(User::find($id)) {
            $user = User::find($id);
            $user->delete();
        }

        return response()->json(['success' => 'Account deleted successfully'], 200);
    }

    /**
     * Hide account.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function hideAccount(Request $request){
    	$validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6|required_with:cpassword|same:cpassword',
            'cpassword' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Email and Password did not match'], 401);
        }

        if (! auth()->user()) {
            return response()->json(['error' => 'Login first'], 403);
        }

        if (! auth()->user()->email == $request->email) {
            return response()->json(['error' => 'Request not allowed'], 406);
        }

        $id = auth()->user()->id;

        $random = Str::random(3);

        if(User::find($id)) {
            User::whereId($id)->update([
                'hidden_at' => \Carbon\Carbon::now()->toDateTimeString(),
                'email' => $random.$request->email,
                'uname' => $random.auth()->user()->uname,
                'pnumber' => $random.auth()->user()->pnumber
            ]);
        }

        return response()->json(['success' => 'Account deleted successfully'], 200);
    }


    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'uname' => 'required|string|between:2,100|unique:users',
            'fname' => 'required|string|between:2,100',
            'lname' => 'required|string|between:2,100',
            'pnumber' => 'required|string|between:2,100|unique:users',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|min:6|required_with:cpassword|same:cpassword',
            'cpassword' => 'required|string|min:6',
        ]);

        if($validator->fails()){
            return response()->json(['error' => $validator->errors()->toJson()], 400);
        }

        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));

        $token = Str::random(64);

        if(User::find(User::where('email', $request->email)->first(['id'])->id)) {
            User::whereId(User::where('email', $request->email)->first(['id'])->id)->update([
                'remember_token' => $token
            ]);
        }

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user,
            'email_verify_token' => $token,
            'uemail' => $user->email,
            'uid' => $user->id,
        ], 201);
    }

    /**
     * Verify email.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function verifyAccount($token)
    {
        $verifyUser = UserVerify::where('token', $token)->first();
  
        $message = 'Sorry your email cannot be identified.';
  
        if(!is_null($verifyUser) ){
            $user = $verifyUser->user;
              
            if(!$user->is_email_verified) {
                $verifyUser->user->is_email_verified = 1;
                $verifyUser->user->save();
                $message = "Your e-mail is verified. You can now login.";
            } else {
                $message = "Your e-mail is already verified. You can now login.";
            }
        }
  
      return redirect()->route('/login')->with('message', $message);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile() {
        return response()->json(auth()->user());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token){
        return response()->json([
            'message' => 'Success',
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

}
