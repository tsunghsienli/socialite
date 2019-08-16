<?php
namespace Laravel\Socialite\Two;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\InvalidStateException;
use GuzzleHttp\ClientInterface;
class LineNotifyProvider  extends AbstractProvider implements ProviderInterface
{
   /**
     * 定義唯一識別名稱.
     */
    const IDENTIFIER = 'LINE_NOTIFY';

    /**
     * 分隔符號
     * 
     * @var string
     */
    protected $scopeSeparator = ' ';


     /**
     * LINE 需求項目
     * 
     * @var array
     */
    protected $scopes = [
      'notify',
    ];

     /**
     * 為LINE 取得認證URL
     * 字串變數 $state
     * @param string $state 
     * 回傳字串
     * @return string 
     */
    protected function getAuthUrl($state){
      return $this->buildAuthUrlFromBase(
        'https://notify-bot.line.me/oauth/authorize', $state
      );
    }
    
    /** 
     * 取得token URL
    */
    protected function getTokenUrl(){
      return 'https://notify-bot.line.me/oauth/token';
    }
protected function parseAccessToken($body){
       return dd($body);
     }
    /**
     * 處理存取TOKEN回應
     * 
     * @param string $code
     * @return json_encode
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'form_params' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUrl,
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret
            ],
        ]);
        return json_decode($response->getBody(),true);
    }


    /**
     * 向LINE提供access token取得使用者資料
     * @param string $token
     * 
     * @return array
     */
    protected function getUserByToken($token)
    {
		
        $response = $this->getHttpClient()->post(
            'https://notify-api.line.me/api/notify', [
            'headers' => [
			 'Content-Type' => 'application/x-www-form-urlencoded',
              'Authorization' => 'Bearer '.$token,
            ],
			'form_params'=>[
				'message'=>'wellcome to join Twstudy',
			],
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }
	public function getAccessToken($body){
    $postKey = (version_compare(ClientInterface::VERSION, '6') === 1) ? 'form_params' : 'body';

    $response = $this->getHttpClient()->post($this->getTokenUrl(), [
        $postKey => $this->getTokenFields($body),
    ]);

    return $this->parseAccessToken($response->getBody());
     }

     protected function getTokenFields($code){
       return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
     }

    /**
     * 將取得回傳之LINE資料放入array變數中
     * 
     * @param array $user
     * 
     * @return \Laravel\Socialite\User
     */
    protected function mapUserToObject(array $user){
      return (new User())->setRaw($user)->map([
	  'access_token'=>$user['access_token'] ?? null,
        'id'       => $user['userId'] ?? $user['sub'] ?? null,
        'nickname' => null,
        'name'     => $user['displayName'] ?? $user['name'] ?? null,
        'avatar'   => $user['pictureUrl'] ?? $user['picture'] ?? null,
        'email'    => $user['email'] ?? null,
      ]);
    }
	 /**
     * {@inheritdoc}
     * 自訂-修正版
     * 取出access_token值
     * @param $body as array
     * @return access_token
     */
    protected function parseLineAccessToken($body)
	  {
		  return Arr::get($body,'access_token');
	  }
   
    /**
     * 定義使用者回傳資料
     * 繼承  laravel\socialite\two\User.php
     */
    public function user(){
      if ($this->hasInvalidState()) {
        throw new InvalidStateException();
      }
      $response = $this->getAccessTokenResponse($this->getCode());
	  
      if ($jwt = $response['id_token'] ?? null) {
        list($headb64, $bodyb64, $cryptob64) = explode('.', $jwt);
        $user = $this->mapUserToObject(json_decode(base64_decode(strtr($bodyb64, '-_', '+/')), true));
      } else {
        $user = $this->mapUserToObject($this->getUserByToken(
          $token = $this->parseLineAccessToken($response)
        ));
      }
	
      $this->credentialsResponseBody = $response;
      
      if ($user instanceof User) {
        $user->setAccessTokenResponseBody($this->credentialsResponseBody);
      }
      // 回傳整個$user資料，$user->setToken()為設定$user陣列變數中的token值
      return $user->setToken($this->parseLineAccessToken($this->credentialsResponseBody));
    }
} 
