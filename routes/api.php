<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group([
    'middleware' => 'api',
    'prefix' => 'auth'

], function ($router) {
    Route::post('/login', [AuthController::class, 'login']);
    Route::post('/register', [AuthController::class, 'register']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    // Route::get('/user-profile', [AuthController::class, 'userProfile'])->middleware(['auth', 'is_verify_email']);
    Route::get('/user-profile', [AuthController::class, 'userProfile']);
    Route::delete('/delete-account', [AuthController::class, 'deleteAccount']);
    Route::delete('/hide-account', [AuthController::class, 'hideAccount']);
    // Route::get('/account/verify/{token}', [AuthController::class, 'verifyAccount'])->name('user.verify');      
});
