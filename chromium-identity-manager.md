# Chromium identity manager information

**Revision Record**

> 输出是一种比较有效的学习方式，但是不能保证完全正确，有什么问题，请不吝赐教，提出来后，
> 咱们共同探讨，这也是另一个比较有效的学习方式。

本文主要是关于Gaia(Google Accounts and ID Administration ID)在Chromium中的管理与使用，其中IdentityManager类即是核心也是中心。

## 几个核心概念

这些概念可以从整体上了解一下ID管理相关的类和方法。

### Accounts

Chromium中账户总是指的Gaia账户，一个账户主要有三个核心信息，其包含在Struct CoreAccountInfo中，
并且只要在IdentityManager中，那么就是有效的。

*   email地址
*   Gaia ID
*   CoreAccountId 这是Chromium内部用的ID，一般和Gaia ID是一样的

在账户添加到Chromium后还会异步地获取一些扩展信息，这些信息包含在CoreAccountInfo的子类Struct AccountInfo中，
包括全名、地域、图标等信息。IdentityManager和其观察者中名字带ExtendedAccountInfo的方法都与这些信息的修改相关。

```cpp
struct CoreAccountInfo {
  ...
  CoreAccountId account_id;
  std::string gaia;
  std::string email;
  ...
}

struct AccountInfo : public CoreAccountInfo {
  ...
  std::string full_name;
  std::string given_name;
  std::string hosted_domain;
  std::string locale;
  std::string picture_url;
  std::string last_downloaded_image_url_with_size;
  gfx::Image account_image;
  ...
}
```

### The Primary Account

主账户就是Chromium与Google云进行同步的账户，之前称为已认证账户。
UPA(Unconsented primary account)是指可能授权的主账户，主要用于展示给用户。
在主账户存在时，UPA就是主账户。在主账户不存在却登陆了多个账户，UPA就是第一个有Refresh Token的登陆账户，
并且Cookie和Token必须是最新的，其主要计算逻辑在SigninManager:

```cpp
class SigninManager : public KeyedService,
                      public signin::IdentityManager::Observer {
  ...
  CoreAccountInfo ComputeUnconsentedPrimaryAccountInfo() const;
  ...
}
```

IdentityManager和其观察者中名字带PrimaryAccount的方法都与主账户的修改相关。

```cpp
class IdentityManager : public KeyedService ... {
  ...
  CoreAccountInfo GetPrimaryAccountInfo(ConsentLevel consent_level) const;
  CoreAccountId GetPrimaryAccountId(ConsentLevel consent_level) const;
  bool HasPrimaryAccount(ConsentLevel consent_level) const;
  bool HasPrimaryAccountWithRefreshToken(ConsentLevel consent_level) const;
  PrimaryAccountMutator* GetPrimaryAccountMutator();
  ...
}
```

### OAuth2 Access and Refresh Tokens

OAuth2是一个认证协议，其有两个Token，分别是短期的Access Token和长期的Refresh Token。
Refresh Token由IdentityManager中的ProfileOAuth2TokenService存储，并且提供Access Token给其他对象使用。
有Refresh Token的账户可以是用户登陆的，也可以是系统登陆的。
IdentityManager和其观察者中名字带RefreshToken的方法都与Refresh Token的修改相关。

```cpp
class IdentityManager : public KeyedService ... {
  ...
  std::unique_ptr<AccessTokenFetcher> CreateAccessTokenFetcherForAccount(...);
  std::unique_ptr<AccessTokenFetcher> CreateAccessTokenFetcherForClient(...);
  void RemoveAccessTokenFromCache(...);

  std::vector<CoreAccountInfo> GetAccountsWithRefreshTokens() const;
  std::vector<AccountInfo> GetExtendedAccountInfoForAccountsWithRefreshToken() const;
  bool HasPrimaryAccountWithRefreshToken(ConsentLevel consent_level) const;
  bool HasAccountWithRefreshToken(const CoreAccountId& account_id) const;
  bool AreRefreshTokensLoaded() const;
  bool HasAccountWithRefreshTokenInPersistentErrorState(const CoreAccountId& account_id) const;
  GoogleServiceAuthError GetErrorStateOfRefreshTokenForAccount(const CoreAccountId& account_id) const;
  ...
}
```

### The Gaia Cookie

这是包含一些账户信息的Cookie，并且能被网页使用。这些账户和OAuth2认证的账户是不一样的，而且在信息的打包上有明显的区别。
IdentityManager和其观察者中有些方法是与其相关的：

```cpp
class IdentityManager : public KeyedService ... {
  ...
  AccountsInCookieJarInfo GetAccountsInCookieJar() const;
  AccountsCookieMutator* GetAccountsCookieMutator();
  ...
}
```

### Mutation of Account State

在IdentityManager中有多个账户修改者对象，如PrimaryAccountMutator，其主要用于修改账户状态，并且账户状态的修改过程是可定制的。
chromium用PrimaryAccountMutator修改主账户，但是在ChromeOS上没有主账户退出。
AccountsCookieMutator用于更新在Cookie中的账户。
在不同的平台上对OAuth2的账户修改是不同的：

*   Windows/Mac/Linux：Chromium内部管理其Refresh Token，并且通过AccountsMutator添加和删除
*   ChromeOS：Chromium通过同步系统的AccoutManager来获取Refresh Token
*   Android：Chromium通过Identityutator来获取Refresh Token
*   iOS：Chromium通过DeviceAccountsSynchronizer来获取google的iOS SSO库的支持

在中有个Mutator的统一类接口：

```cpp
class IdentityMutator {
  ...
  std::unique_ptr<PrimaryAccountMutator> primary_account_mutator_;
  std::unique_ptr<AccountsMutator> accounts_mutator_;
  std::unique_ptr<AccountsCookieMutator> accounts_cookie_mutator_;
  std::unique_ptr<DeviceAccountsSynchronizer> device_accounts_synchronizer_; //这个一般用iOS上
  ...
}
```

## ID核心服务——IdentityManager

IdentityManager是KeyedService子类，在Chromium中以服务形式存在，在//chrome中可以通过IdentityManagerFactory::GetForProfile()获取，
因为每一个Profile都有一个对应的IdentityManager，并且在Profile创建时被建立的。在初始化时IdentityManager会从WebData中获取已登陆的用户。

### 监听账户的变化

IdentityManager使用经典的观察者设计模式来传播账户的变化，观察者接口为：

```cpp
class IdentityManager::Observer {
  //主账户发生了变化
  virtual void OnPrimaryAccountChanged(const PrimaryAccountChangeEvent& event_details) {}
  //OAuth2账户相关的变化
  virtual void OnRefreshTokenUpdatedForAccount(const CoreAccountInfo& account_info) {}
  virtual void OnRefreshTokenRemovedForAccount(const CoreAccountId& account_id) {}
  virtual void OnErrorStateOfRefreshTokenUpdatedForAccount(const CoreAccountInfo& account_info, const GoogleServiceAuthError& error) {}
  virtual void OnRefreshTokensLoaded() {}
  virtual void OnEndBatchOfRefreshTokenStateChanges() {}
  //在Cookie中的账户发生了变化
  virtual void OnAccountsInCookieUpdated(const AccountsInCookieJarInfo& accounts_in_cookie_jar_info, const GoogleServiceAuthError& error) {}
  virtual void OnAccountsCookieDeletedByUserAction() {}
  //账户的扩展信息发生了变化
  virtual void OnExtendedAccountInfoUpdated(const AccountInfo& info) {}
  virtual void OnExtendedAccountInfoRemoved(const AccountInfo& info) {}
  //服务关闭
  virtual void OnIdentityManagerShutdown(IdentityManager* identity_manager) {}
}
```

注册了IdentityManager的观察者主要是：

*   FamilyLinkUserMetricsProvider用户上报
*   AccountInvestigator用于监视Cookie账户并做Report，也是一个KeyedService
*   GAIAInfoUpdateService用于修改Profile中的内容，也是一个KeyedService
*   AdvancedProtectionStatusManager用于保护主账户，也是一个KeyedService
*   SigninProfileAttributesUpdater用于改变登陆后属性，也是一个KeyedService
*   SigninManager用于找到UPA，也是一个KeyedService
*   PersonalDataManager用于数据填充，也是一个KeyedService
*   IdentityAPI用于传播登陆状态
*   RendererUpdater用于更新Renderer的配置，也是一个KeyedService
*   GCMProfileService用于更新GCM(Google Cloud Messaging)状态，也是一个KeyedService
*   TrustedVaultAccessTokenFetcherFrontend用于在UI线程中获取Access Token
*   StandaloneTrustedVaultBackend保存Keys
*   SigninErrorController用于跟踪验证状态，也是一个KeyedService
*   AccountReconcilor用于协调Cookie和OAuth2账户一致
*   AboutSigninInternals为chrome://signin-internals/提供数据
*   SyncServiceImpl
*   PasswordModelTypeController
*   SyncAuthManager跟踪用于同步的账户
*   UnifiedConsentService
*   UserPolicySigninService
*   SyncSessionDurationsMetricsRecorder
*   ProfileIdentityProvider
*   AvatarToolbarButtonDelegate
*   OneGoogleBarService::SigninObserver
*   PasswordStoreSigninNotifierImpl
*   LogoServiceImpl

### 拥有的服务

IdentityManager是核心也是中心，其通过调用其他服务来实现对账户的管理，其拥有的主要服务有：

*   AccountTrackerService检索或缓存Gaia账户信息
*   ProfileOAuth2TokenService存储Refresh Token，并且管理这Access Token
*   GaiaCookieManagerService管理在Cookie jar中的Gaia账户
*   AccountFetcherService管理着获取用户信息的请求

### 存储Refresh Token

ProfileOAuth2TokenService在创建时会传入ProfileOAuth2TokenServiceDelegate，其大部分的业务实现都会调用这个Delegate，
而且在开启DICE的情况下，Dategate是其子类MutableProfileOAuth2TokenServiceDelegate:

```cpp
class MutableProfileOAuth2TokenServiceDelegate : public ProfileOAuth2TokenServiceDelegate ... {
  ...
  void LoadCredentials(const CoreAccountId& primary_account_id) override;
  void UpdateCredentials(const CoreAccountId& account_id, const std::string& refresh_token) override;
  void RevokeAllCredentials() override;
  void RevokeCredentials(const CoreAccountId& account_id) override;
  void ExtractCredentials(ProfileOAuth2TokenService* to_service, const CoreAccountId& account_id) override;

  bool RefreshTokenIsAvailable(const CoreAccountId& account_id) const override;
  std::string GetRefreshToken(const CoreAccountId& account_id) const;
  ...
}
```

### 使用Access Token发送请求

ProfileOAuth2TokenService通过调用OAuth2AccessTokenManager实现Access Token的管理，
OAuth2AccessTokenManager会在缓存的Access Token中找到账户对应的Access Token，如果没找到会用存储的Refresh Token发起获取请求，
在更新Access Token后会调用OAuth2AccessTokenManager::Consumer中的回调，
这些逻辑大部分在OAuth2AccessTokenManager中实现，其接口为：

```cpp
class OAuth2AccessTokenManager {
  ...
  std::unique_ptr<Request> StartRequest(const CoreAccountId& account_id, const ScopeSet& scopes, Consumer* consumer);
  std::unique_ptr<Request> StartRequestForClient( const CoreAccountId& account_id, const std::string& client_id, const std::string& client_secret, const ScopeSet& scopes, Consumer* consumer);
  std::unique_ptr<Request> StartRequestWithContext( const CoreAccountId& account_id, scoped_refptr<network::SharedURLLoaderFactory> url_loader_factory, const ScopeSet& scopes, Consumer* consumer);
  ...
}
```

## //google\_api/gaia目录中的源码

这个目录下是Gaia与google服务器联系相关的代码，如果要修改为定制的ID，那么大部分应该是修改这里的代码，
比如gaia\_url中是google服务器的地址，gaia\_auth\_fetcher发送Gaia相关的请求并解码后给GaiaAuthConsumer的子类进一步处理，
而且Gaia Access Token相关的调用也在这里，OAuth2AccessTokenManager的源码文件oauth2\_access\_token\_manager.h/.cc。

### 使用Google Accounts APIs鉴权

GaiaAuthFetcher类封装了对Google Accounts APIs的调用了

```cpp
class GaiaAuthFetcher {
  ...
  void StartRevokeOAuth2Token(const std::string& auth_token);
  void StartAuthCodeForOAuth2TokenExchange(const std::string& auth_code);
  void StartAuthCodeForOAuth2TokenExchangeWithDeviceId(const std::string& auth_code, const std::string& device_id);
  void StartGetUserInfo(const std::string& lsid);
  void StartMergeSession(const std::string& uber_token, const std::string& external_cc_result);
  void StartTokenFetchForUberAuthExchange(const std::string& access_token);
  void StartOAuthLogin(const std::string& access_token, const std::string& service);
  void StartOAuthMultilogin(gaia::MultiloginMode mode, const std::vector<MultiloginTokenIDPair>& accounts, const std::string& external_cc_result);
  void StartListAccounts();
  void StartLogOut();
  virtual void StartCreateReAuthProofTokenForParent(const std::string& child_oauth_access_token, const std::string& parent_obfuscated_gaia_id, const std::string& parent_credential);
  ...
}
```

在GaiaAuthFetcher中有一系列Google Accounts APIs的url常量作为网络访问地址，其值都是从GaiaUrls类中获取的常量值。
在Start\*接口实现中，首先通过Make\*接口创建要GET/POST的参数，然后用对应的网络地址常量，
调用private接口创建网络访问请求：

```cpp
  virtual void CreateAndStartGaiaFetcher(
      const std::string& body,
      const std::string& body_content_type,
      const std::string& headers,
      const GURL& gaia_gurl,
      network::mojom::CredentialsMode credentials_mode,
      const net::NetworkTrafficAnnotationTag& traffic_annotation);
```

CreateAndStartGaiaFetcher实现中，首先创建ResourceRequest，然后将Gaia的Cookie添加到ResourceRequest,
然后为ResourceRequest创建对应的SimpleURLLoader进行网络访问，网络返回会异步地传个private方法OnURLLoadComplete，

```cpp
  void OnURLLoadComplete(std::unique_ptr<std::string> response_body);
  void OnURLLoadCompleteInternal(net::Error net_error, int response_code, std::string response_body);
  void DispatchFetchedRequest(const GURL& url, const std::string& data, net::Error net_error, int response_code);
```

OnURLLoadComplete解析出response\_code和data后，会调用OnURLLoadCompleteInternal找到original\_url，
然后调用DispatchFetchedRequest函数，通过original\_url来分发网络返回到对应的处理函数，
对应的函数会在解析data中的数据后，调用GaiaAuthConsumer对应的回调进行下一步的业务逻辑。

### AuthCode换取OAuth2Token网络数据

静态函数GaiaAuthFetcher::MakeGetTokenPairBody实现了请求body打包，参数是auth\_code,device\_id,
函数中通过kOAuth2CodeToTokenPairBodyFormat:"scope=%s\&grant\_type=authorization\_code\&client\_id=%s\&client\_secret=%s\&code=%s"进行打包，
其中scope值为<https://www.google.com/accounts/OAuthLogin，>
client\_id值为google api keys中主ClientID，client\_secret值为google api keys中主ClientSecret,
code值是参数auth\_code，
如果参数device\_id不为空，那么在format后添加kOAuth2CodeToTokenPairDeviceIdParam:"device\_id=%s\&device\_type=chrome"
OnOAuth2TokenPairFetched是网络返回回调，在其中调用ExtractOAuth2TokenPairResponse函数来解析返回的data，
返回的数据是以JSON方式打包，其中需要解析的键值有：refresh\_token，access\_token，expires\_in，id\_token。
在获取的id\_token后，从中解码出kChildAccountServiceFlag和kAdvancedProtectionAccountServiceFlag，
这样就能创建结果ClientOAuthResult。

```cpp
struct GaiaAuthConsumer::ClientOAuthResult {
  ...
  std::string refresh_token;
  std::string access_token;
  int expires_in_secs;
  bool is_child_account;
  bool is_under_advanced_protection;
  ...
}
```

## google api keys

要访问google的服务需要google api keys，但是从69版本开始通过OAuth2登陆Chromium被限制了。
参考：<p><https://www.chromium.org/developers/how-tos/api-keys></p>

## DICE

在linux、mac、win、fuchsia下Dice是打开的，在android、chromeos、ios下打开的是mirror。

## 同步登陆失败分析

同步登陆需要将Cookie账户提高成OAuth2账户，进一步提高成Primary Account，通过跟踪分析，Cookie成功了但是OAuth2失败了。

### 网络请求对比

这是Chrome同步登陆时，网络的截图：

![Chrome网络截图](./chrome.png)

这是Dingtao同步登陆时，网络的截图：

![Dingtao网络截图](./dingtao.png)

从网络截图中可以很明显地看出，Chrome在登陆后有<p><https://www.googleapis.com/oauth2/v4/token></p>这个URL的访问，
这里有两个可能Dingtao网络中没有这个访问，一是Dingtao在逻辑处理时没有发出这个请求，
一是发出了这个请求，但是google服务器没有给返回，从google api key看第二种是最有可能的。

### 同步登陆后账户的状态对比

这是Chrome登陆后，账户状态截图：

![Chrome账户状态截图](./chrome_accounts.png)

这是Dingtao登陆后，账户状态截图：

![Dingtao账户状态截图](./dingtao_accounts.png)

从截图中可以看出Dingtao并没有获取到Refresh Token，因此同步登陆失败了。

### 模拟google chrome的key值

从抓包和log中提取出了google chrome的client\_id和client\_secret，这样在dingtao中模拟这两个值就能登陆成功，
但是还不能从google服务器上同步数据。

```cpp
    client_id:77185425430.apps.googleusercontent.com
client_secret:OTJgUOQcT7lO7GsGZq2G4IlT
```

## 同步登陆流程分析

在点击profile弹出窗口中‘开启同步功能’按钮后，点击事件会分发到ProfileMenuView::OnSigninButtonClicked，
然后会调用signin\_ui\_util中的函数进行用户查找，然后调用SigninViewController中的函数在新的Tab中打开<https://accounts.google.com/signin/chrome/sync?ssp=1>
具体流程如下：

```cpp
ProfileMenuView::OnSigninButtonClicked //button事件处理函数
signin_ui_util::EnableSyncFromMultiAccountPromo //查找是否有已经登陆的账户
signin_ui_util::SigninUiDelegateImplDice::ShowSigninUI //判断是打开同步Tab还是添加账户Tab
SigninViewController::ShowDiceSigninTab //确定Gaia地址，并打开Tab访问
```

在打开登陆页面过程前，ChromeContentBrowserClient::CreateURLLoaderThrottles会为网络访问创建signin::URLLoaderThrottle来hook三个网络处理函数：
WillStartRequest，WillRedirectRequest和WillProcessResponse，并且调用HeaderModificationDelegate来修改账户相关的http header，
在DICE下会调用DiceHeaderHelper来添加http header，其中device\_id来自于Prefs，并且每次登出时会重新被创建：

```cpp
ChromeContentBrowserClient::CreateURLLoaderThrottles //创建网络访问的节流器
signin::URLLoaderThrottle //sigin节流器用于hook网络访问以便于修改http header
HeaderModificationDelegate //与Profile对应，并且调用http header请求和响应的处理函数
FixAccountConsistencyRequestHeader //添加或移除http header
AppendOrRemoveDiceRequestHeader //处理Dice相关的http header
DiceHeaderHelper.ShouldBuildRequestHeader //判断当前url是否属于Gaia
DiceHeaderHelper.BuildRequestHeader //建立http header中的value
DiceHeaderHelper.AppendOrRemoveRequestHeader //将value添加到X-Chrome-ID-Consistency-Request
//header示例
//x-chrome-id-consistency-request: version=1,client_id=77185425430.apps.googleusercontent.com,device_id=8cec37c8-1f40-44cc-bb02-c6e304445560,signin_mode=all_accounts,signout_mode=show_confirmation
```

打开网页后需要输入账户名和密码，会打开<https://accounts.google.com/CheckCookie?continue=https%3A%2F%2Faccounts.google.com%2Fsignin%2Fchrome%2Fsync%2Ffinish%3Fcontinue%3Dhttps%253A%252F%252Fwww.google.com%252F%26est%3DANiM2xS0zq2HM6mpxxbN_A>,
然后重定向到<https://accounts.google.com/signin/chrome/sync/finish?continue=https%3A%2F%2Fwww.google.com%2F&est=ANiM2xQ5jMO3kgTe1TBCsBDyfU2rzGqNznIcuMBFQJCX3ll3K6wkVSnj5hOyiPy66OHnwkFFjbq0Mw8iJI6VL_w，>
然后重定向到<https://www.google.com/，再打开chrome://sync-confirmation/>
在<https://accounts.google.com/signin/chrome/sync/finish返回中会有Gaia自定义http> header：X-Chrome-ID-Consistency-Response，
通过这个头的值就可以调用BuildDiceSigninResponseParams创建DiceResponseParams进行用户添加。

```cpp
sigin::URLLoaderThrottle::WillRedirectRequest //hook到网络重定向
ProcessAccountConsistencyResponseHeaders //根据自定义header创建DiceResponseParams
//header示例
//x-chrome-id-consistency-response: action=SIGNIN,id=102877287560284957551,email=wzm.dingos@gmail.com,authuser=0,authorization_code=4/0AdQt8qjK5gAUFG4sdHF5X5FO3DpPC4vTwqIHQUOsbAshnw3KFVpGsewD6XpDI8UGigIvtQ
//X-Chrome-ID-Consistency-Response: action=ENABLE_SYNC,id=102877287560284957551,email=wzm.dingos@gmail.com,authuser=0
```

创建DiceResponseParams后，会将其做为ProcessDiceHeader函数参数，并分发到UI线程，执行时会创建调用DiceResponseHandler::ProcessDiceHeader函数，
并且创建ProcessDiceHeaderDelegate做为参数之一，在DiceResponseHandler中会创建DiceTokenFetcher来换取Refresh Token，这是通过GaiaAuthFetcher::StartAuthCodeForOAuth2TokenExchange
发起访问网络的请求，请求成功换取Refresh Token后会通知signin::IdentityManager中的AccountsMutator进行账户添加或更新，
然后调用ProcessDiceHeaderDelegateImpl::EnableSync打开同步，其中会创建TurnSyncOnHelper，然后打开新的Tab或网页。

```cpp
ProcessDiceHeader //处理网络返回的自定义http header value
DiceResponseHandler::ProcessDiceHeader //根据返回的action调用不同的处理函数
DiceResponseHandler::ProcessEnableSyncHeader //等待之前创建的DiceTokenFetcher返回
DiceResponseHandler::DiceTokenFetcher::OnClientOAuthSuccess //Refresh Token成功换取
DiceResponseHandler::OnTokenExchangeSuccess //处理新的Refresh Token
signin::IdentityManager::GetAccountsMutator()->AddOrUpdateAccount //添加或更新账户
ProcessDiceHeaderDelegateImpl::EnableSync //打开同步功能
```

## 打开www\.google.com获取账户的流程

在初始化时，会从WebData中获取同步账户的Refresh Token，

```cpp
MutableProfileOAuth2TokenServiceDelegate::OnWebDataServiceRequestDone //读取WebData成功的回调
MutableProfileOAuth2TokenServiceDelegate::LoadAllCredentialsIntoMemory //加载有Refresh Token的账户到内存
signin::IdentityManager::OnRefreshTokenAvailable //分发有效Refresh Token事件
AccountFetcherService::OnRefreshTokenAvailable //更新Refresh Token以便于获取Access Token
gcm::AccountTracker::OnRefreshTokenUpdatedForAccount //gcm添加账户
```

在网络启动后，会调用GaiaCookieManagerService::StartFetchingListAccounts从网络上获取当前用户的列表，
获取成功后会调用IdentityManager::OnGaiaAccountsInCookieUpdated分发Gaia cookie Accounts更新。

```cpp
ChromeSigninClient::OnConnectionChanged //网络连接回调
GaiaCookieManagerService::StartFetchingListAccounts //启动获取当前用户列表
GaiaAuthFetcher::StartListAccounts //访问网络获取用户列表
GaiaCookieManagerService::OnListAccountsSuccess //用户列表获取成功
IdentityManager::OnGaiaAccountsInCookieUpdated //分发cookie用户通知
//http示例
//https://accounts.google.com/ListAccounts?gpsia=1&source=ChromiumBrowser&json=standard
//cookie: 1P_JAR=2022-08-11-10; SID=NQi7LcU7AY-KG783C2Yx7bXMh_sW06fKfUNC_VGxTIm2hy...
```

点登录按键后，a标签打开新页面

```cpp
//https://accounts.google.com/ServiceLogin?hl=zh-CN&passive=true&continue=https://www.google.com.hk/&ec=GAZAmgQ
//https://accounts.google.coAIzaSyB4OXx0GPzBeBR5qolRy4_xBwJUXa5G-b8m.hk/accounts/SetSID?ssdc=1&sidt=ALWU2ct8EPY%2BzgyMkhsYTw5O%2ByfJHmsBI1x6oV%2FCIv7%2F4V96ODzCqWf5rLNjsVfJ8IDWL7P%2BC5dABLW6QfbXdenRrDTCTCGUHho3hwcyCq7XFRnx8I2xGM4MKehYOAXrCIl1O5DsdC6k61pPzZSE16LW5xN0g%2BU3al1BM%2FpvM8CFGvMtpxgaWVUIJ65Dc%2BUNCx1Sxbf21BH8NtkIAhfsJtY%2FrqL6TpWrlt%2B%2BrFall4nT8gpSIgW00OFYTlsiyj9vTjbTXQP3TV%2F1RcybnoFGy%2BwHuKaHCgb%2B8ixhZtJt2%2BzbWZIQ0hfKYHQ26fC3htIoQXnSD0dXRQeV%2BDugDX7a0J%2FaHX7N0Vx1%2Fe3VquJ81XNBn%2F5vsqCAlRAjdaEd8%2FdSRTxNfU%2FbsbZWsgrfvtY9E1TNjY544rrMAUJ8S%2BY%2BpFsldGqqHuqM4ES6BKn1Z9ByGQpmETWiT2GYwUDUv8nogTIKcaAy1WM5yQ%3D%3D&continue=https%3A%2F%2Fwww.google.com.hk%2F%3Fpli%3D1
```

## Chromium启动时发起的Gaia请求

在浏览器初始化网络后，调用GaiaCookieManagerService::InitCookieListener，会在CookieManager中添加url为"<https://google.com/"，>
name为"SAPISID"的监听，在网络连接后调用GaiaCookieManagerService::StartFetchingListAccounts发送一个list请求，
从WebData获取到账户的Refresh Token后会调用AccountFetcherService::OnRefreshTokensLoaded来刷新账户信息，
每个账户会调用AccountCapabilitiesFetcherGaia::StartImpl来获取Account Capabilities的Access Token，
这会调用OAuth2AccessTokenManager::StartRequestForClientWithContext先看看有Token缓存不，
然后再调用GaiaAccessTokenFetcher::CreateExchangeRefreshTokenForAccessTokenInstance发起请求。

```cpp
GaiaCookieManagerService::InitCookieListener //为google添加Cookie监听器
GaiaCookieManagerService::StartFetchingListAccounts //发起list accounts请求
WebDataRequestManager::RequestCompletedOnThread //WebData获取成功
MutableProfileOAuth2TokenServiceDelegate::FinishLoadingCredentials //获取WebData中的Refresh Token
AccountFetcherService::OnRefreshTokensLoaded //Refresh Token加载完成
AccountFetcherService::RefreshAccountInfo //刷新账户信息
AccountCapabilitiesFetcherGaia::StartImpl //获取账户信息的Access Token
OAuth2AccessTokenManager::StartRequestForClientWithContext //如果Cache中没有，那么从网上获取
GaiaAccessTokenFetcher::CreateExchangeRefreshTokenForAccessTokenInstance //发起Access Token请求
AccountFetcherService::StartFetchingUserInfo //获取用户信息
SyncAuthManager::RequestAccessToken //获取同步的Access Token
GCMAccountTracker::GetToken //获取GCM的Access Token
GaiaCookieManagerService::ExternalCcResultFetcher::Start //获取网络检查信息
```

## ListAccounts请求分析

ListAccounts请求是Chromium比较重要的请求，起到串起登陆的流程的作用。
在Chromium启动时会发出一个ListAccounts请求，其中的Cookie是Chromium关闭前保存的，如上分析。
其次在Cookie的"<https://google.com/"监听器中，只要cookie有变化，删除或添加，那么都会重新发一个ListAccounts请求。>
在获取用户列表成功后，会通知signin::IdentityManager::OnGaiaAccountsInCookieUpdated，
这里会调用AccountReconcilor::StartReconcile来同步OAuth2到Cookie中，
其中会调用到signin::AccountsCookieMutatorImpl::SetAccountsInCookie发起将账户设置到Cookie的逻辑，
逻辑首先调用signin::OAuthMultiloginHelper::StartFetchingTokens开始获取Access Token，
其中会调用ProfileOAuth2TokenService::StartRequestForMultilogin判断是从网络获取，还是直接将Refresh Token做为Access Token，
获取到Access Token后调用signin::OAuthMultiloginHelper::StartFetchingMultiLogin发起登陆请求，
登陆请求返回中会有一些Cookie，通过signin::OAuthMultiloginHelper::StartSettingCookies设置到CookieManager中。

```cpp
GaiaCookieManagerService::OnCookieChange //Cookie发生了变化
GaiaCookieManagerService::StartFetchingListAccounts //开始ListAccounts请求
GaiaCookieManagerService::OnListAccountsSuccess //请求返回成功
signin::IdentityManager::OnGaiaAccountsInCookieUpdated //分发账户变化通知
AccountReconcilor::StartReconcile //协调OAuth2账户成Cookie账户
signin::AccountsCookieMutatorImpl::SetAccountsInCookie //开始设置账户到Cookie中
signin::OAuthMultiloginHelper::StartFetchingTokens //首先要获取账户的Access Token
ProfileOAuth2TokenService::StartRequestForMultilogin //如果有Refresh Token那么做为Access Token进行下一步
signin::OAuthMultiloginHelper::StartFetchingMultiLogin //收到Access Token后发起登陆请求
signin::OAuthMultiloginHelper::StartSettingCookies //收到登陆成功返回后将其数据设置到Cookie中
GaiaCookieManagerService::StartFetchingListAccounts //Cookie发生变化发起新的ListAccounts请求
```

## ChromeOS上Chromium账户管理

### 自定义Http Header

在ChromeOS登陆后，每次访问google服务都会带上一个自定义Http Header用于表示当前的登陆账户，名字为X-Chrome-Connected
这样服务可以调用一些Native UI。但是在Chromium中也有一些情况会有这个Http Header，
如在访问“<https://drive.google.com”和“https://docs.google.com”服务时，这是为了开启离线模式。>

```cpp
x-chrome-connected: source=Chrome,id=113934407622812037815,mode=0,enable_account_consistency=false,consistency_enabled_by_default=false
```

### LACROS

这是从ChromeOS解耦出来的Browser，可以在ChromeOS和Linux上运行，因此Linux And ChRome OS而命名为LACROS。
这样在ChromeOS上有两个版本一个是IS\_CHROMEOS\_LACROS，一个是IS\_CHROMEOS\_ASH，
在账户管理方面有细微差别，但是都通过mojo调用了account\_manager::AccountManager。

### 启动时获取账户信息

ChromeOS启动后会提示登陆，登陆成功后会调用ash::OAuth2TokenInitializer::Start获取账户的Refresh Token并保存到AccountManager中，
AccountManager会通知ProfileOAuth2TokenServiceDelegateChromeOS，并更新ash::OAuth2LoginManager,
首先发起ListAccounts请求，请求返回后先通过AccountReconcilor进行账户对帐，同时开始将账户添加到Cookie中，
这样就会发起三个请求，一个是登陆，一个是获取Ubertoken，一个是合并Session。

```cpp
ash::OAuth2TokenInitializer::Start //登陆后开始获取Refresh Token
signin::ProfileOAuth2TokenServiceDelegateChromeOS::FinishLoadingCredentials //被通知Refresh Tokon有更新
ash::OAuth2LoginManager::OnRefreshTokenUpdatedForAccount //开始验证Refresh Token
GaiaCookieManagerService::StartFetchingListAccounts //发起ListAccounts请求
AccountReconcilor::OnAccountsInCookieUpdated //进行账户的对账
ash::OAuth2LoginManager::OnListAccountsSuccess //请求返回后验证当前Token状态
signin::AccountsCookieMutatorImpl::AddAccountToCookieWithToken //开始将账户添加到Cookie
account_manager::AccountManagerFacadeImpl::AccessTokenFetcher::OnAccessTokenFetchComplete //返回登陆Access Token
signin::OAuthMultiloginHelper::StartFetchingMultiLogin //发起登陆请求
GaiaCookieManagerService::StartFetchingUbertoken //发起获取Uber Token请求
GaiaCookieManagerService::StartFetchingMergeSession //发起合并Session请求
```

从上面过程看，ChromeOS和Chromium登陆过程主要有三个差异：

*   获取Refresh Token的地方不同，ChromeOS是在用户管理中发起请求并保存
*   Chromium通过mojo到ChromeOS获取Access Token
*   在发起登陆过程中，还发起了添加账户的请求，分成了两步，一个获取Uber Token，一是合并Session

### ChromeOS启动时网络请求

ChromeOS启动后先打开WebUI页面，让用户进行语言设置，然后打开邮箱输入页面，因为Profile默认是不记录历史，因此没有自定义的http header：

    url：
    https://accounts.google.com/embedded/setup/v2/chromeos?chrometype=chromedevice&client_id=77185425430.apps.googleusercontent.com&client_version=107.0.5278.0&platform_version=0.0.0.0&endpoint_gen=1.0&mi=ee&is_first_user=true&hl=en-US&use_native_navigation=1

    request header：
    sec-ch-ua: "Chromium";v="107", "Not=A?Brand";v="24"
    sec-ch-ua-mobile: ?0
    sec-ch-ua-platform: "Chromium OS"
    upgrade-insecure-requests: 1
    user-agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
    accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
    sec-ch-ua-full-version: "107.0.5278.0"
    sec-ch-ua-arch: "x86"
    sec-ch-ua-model: ""
    sec-ch-ua-bitness: "64"
    sec-fetch-site: none
    sec-fetch-mode: navigate
    sec-fetch-user: ?1
    sec-fetch-dest: document
    accept-encoding: gzip, deflate, br
    accept-language: en-US,en;q=0.9

    respone header：
    HTTP/1.1 200
    content-type: text/html; charset=utf-8
    x-frame-options: DENY
    vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site
    google-accounts-embedded: 1
    cache-control: no-cache, no-store, max-age=0, must-revalidate
    pragma: no-cache
    expires: Mon, 01 Jan 1990 00:00:00 GMT
    date: Mon, 05 Sep 2022 07:18:03 GMT
    content-encoding: gzip
    strict-transport-security: max-age=31536000; includeSubDomains
    report-to: {"group":"coop_gse_qebhlk","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gse_qebhlk"}]}
    content-security-policy: script-src 'report-sample' 'nonce-Ou2wWlh39pj0wcn0pAy3CQ' 'unsafe-inline' 'unsafe-eval';object-src 'none';base-uri 'self';report-uri /cspreport
    content-security-policy: require-trusted-types-for 'script';report-uri /cspreport
    cross-origin-opener-policy-report-only: same-origin; report-to="coop_gse_qebhlk"
    x-content-type-options: nosniff
    x-xss-protection: 1; mode=block
    server: GSE
    set-cookie: __Host-GAPS=1:QJtsPNVVi9AXmF3hMiBxUbNcKYa7cg:MvCW1tP-XdjZ2Toa;Path=/;Expires=Wed, 04-Sep-2024 07:18:03 GMT;Secure;HttpOnly;Priority=HIGH
    set-cookie: GEM=CgptaW51dGVtYWlkEOfYjeSwMA==; Path=/; Secure; HttpOnly
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

在输入账号和密码后会调用登录接口：

    url：
    https://accounts.google.com/_/signin/challenge?hl=en&TL=AKqFyY9K42O9xMvb3WqJeVqq-CmO9lgI6PYcs1dXVt6Bgm3mzhzhNFCqD7T0J3nc&_reqid=155101&rt=j

    request header:
    content-length: 2810
    sec-ch-ua: "Chromium";v="107", "Not=A?Brand";v="24"
    x-same-domain: 1
    content-type: application/x-www-form-urlencoded;charset=UTF-8
    google-accounts-xsrf: 1
    sec-ch-ua-mobile: ?0
    user-agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
    sec-ch-ua-platform: "Chromium OS"
    accept: */*
    origin: https://accounts.google.com
    sec-fetch-site: same-origin
    sec-fetch-mode: cors
    sec-fetch-dest: empty
    referer: https://accounts.google.com/signin/v2/challenge/pwd?chrometype=chromedevice&client_id=77185425430.apps.googleusercontent.com&client_version=107.0.5278.0&platform_version=0.0.0.0&endpoint_gen=1.0&mi=ee&is_first_user=true&hl=en-US&use_native_navigation=1&flowName=GlifSetupChromeOs&cid=1&navigationDirection=forward&TL=AKqFyY9K42O9xMvb3WqJeVqq-CmO9lgI6PYcs1dXVt6Bgm3mzhzhNFCqD7T0J3nc
    accept-encoding: gzip, deflate, br
    accept-language: en-US,en;q=0.9
    cookie: GEM=CgptaW51dGVtYWlkEOfYjeSwMA==; NID=511=bjL3i-NM-poEuv1lEQFVKOEaj0wK75V9hQ_Cwxvq8ZzLsKB7KUIBV5IeWXu7pSjJaULDfZAyYektdkRPW-TrLWM2FU_-N3UefBCZXo1iWfyVTH9PvVeJeasrBXmtW0bJeHx0tGxkNV-b-PgnIryWmmargvruXiltlcGeNi99ZQ0; __Host-GAPS=1:MUZAP-0HyWSLWI-VIbCOHIsCIQ39rw:dV9qYfRR61jksjZi

    respone header:
    HTTP/1.1 200
    content-type: application/json; charset=utf-8
    x-frame-options: DENY
    vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site
    google-accounts-signin: email="pwaruntime@gmail.com", sessionindex=0, obfuscatedid="113934407622812037815"
    cache-control: no-cache, no-store, max-age=0, must-revalidate
    pragma: no-cache
    expires: Mon, 01 Jan 1990 00:00:00 GMT
    date: Mon, 05 Sep 2022 07:18:32 GMT
    x-content-type-options: nosniff
    content-encoding: gzip
    strict-transport-security: max-age=31536000; includeSubDomains
    report-to: {"group":"coop_gse_qebhlk","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gse_qebhlk"}]}
    content-security-policy: require-trusted-types-for 'script';report-uri /cspreport
    cross-origin-opener-policy-report-only: same-origin; report-to="coop_gse_qebhlk"
    x-xss-protection: 1; mode=block
    server: GSE
    set-cookie: __Host-GAPS=1:WVjhJYXBMiGLqNccUbH5z9Esw0uU_w:OO43SkCDUeb1x7Gp;Path=/;Expires=Wed, 04-Sep-2024 07:18:32 GMT;Secure;HttpOnly;Priority=HIGH
    set-cookie: oauth_code=4/0AdQt8qjdiIXiQtvPqxTpoR0yY5FdGjEeW-4Q2Pw_8f93QxkCaJsY8SJDkeHVNJxZDbhzug;Path=/;Secure;HttpOnly
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

其中oauth\_code会通过监听cookie的方式获取，获取到oauth\_code后，会通过base::GenerateGUID生成device\_id，然后换取Refresh Token：

    url：
    https://www.googleapis.com/oauth2/v4/token

    request header:
    content-type: application/x-www-form-urlencoded
    sec-fetch-site: none
    sec-fetch-mode: no-cors
    sec-fetch-dest: empty
    user-agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
    accept-encoding: gzip, deflate, br

    body:
    scope=https://www.google.com/accounts/OAuthLogin&grant_type=authorization_code&client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&code=4/0AdQt8qi6eX5YI90x_VtJNrB8i

    respone header:
    HTTP/1.1 200
    expires: Mon, 01 Jan 1990 00:00:00 GMT
    pragma: no-cache
    cache-control: no-cache, no-store, max-age=0, must-revalidate
    date: Mon, 05 Sep 2022 07:18:33 GMT
    content-type: application/json; charset=utf-8
    vary: Origin
    vary: X-Origin
    vary: Referer
    content-encoding: gzip
    server: scaffolding on HTTPServer2
    content-length: 1236
    x-xss-protection: 0
    x-frame-options: SAMEORIGIN
    x-content-type-options: nosniff
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

    data:
    {
      "access_token": "ya29.a0AVA9y1u-j8-Ct_gH7XG6rVodF_pRt92sJGcFVH2IChEJsHxzGx7Z7zc0_z0erg_WiXZibV_6sijO7wzQ9B0BhtbeY8XcRCB8KP_Zhwkt6kavuT9ro87oqNvAfgtAICNwJuH44vPG6Dt9uApaq8n5wm88EYOt5SPEw5uwhJD7kwmzOAiCHxmLy8GSMCovG-vyudfSlknc7DaR1RKrWg8R-RLim_hCQy_eXwwizvRfR6h5LJqonlGLsUO-8V2tmNyXUPAaCgYKATASAQASFQE65dr8O0xhGikCM1Un8TP7_zWBQQ0266",
      "expires_in": 82189,
      "refresh_token": "1//0ep6aVs1hei7dCgYIARAAGA4SNwF-L9IrjDlmnDV9FLpSnHaZJzZE6zMdgObGx97yTxSkonss_69N4d6RyZB8Ode2THxlKz4FhJo",
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer",
      "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU4NDdkOTk0OGU4NTQ1OTQ4ZmE4MTU3YjczZTkxNWM1NjczMDJkNGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3NzE4NTQyNTQzMC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6Ijc3MTg1NDI1NDMwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEzOTM0NDA3NjIyODEyMDM3ODE1IiwiZW1haWwiOiJwd2FydW50aW1lQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiTHVHX2IxRi1DT1RqRkFoY21MM3FEdyIsIm5hbWUiOiJEYW8gRGluZyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BSXRidm1uNnNyaDlTOTdNcjlCM0dYQ3VTcGdvOE1xNlRnb2EwMUNrX2pVXz1zOTYtYyIsImdpdmVuX25hbWUiOiJEYW8iLCJmYW1pbHlfbmFtZSI6IkRpbmciLCJsb2NhbGUiOiJ6aC1DTiIsInNlcnZpY2VzIjpbXSwiaWF0IjoxNjYyNDM1NzQ1LCJleHAiOjE2NjI0MzkzNDV9.Nq-ls-0nrhW7PiYk3Q4bNZBMXJA2EttKh4dH2KGP6RDVaKIQCNHCt5WxQADofzfLW7hUBjWoUIZ8-aMswjqyu97N0-t22CQRr6o5tSKYquOmaFKD2xrGye7sD04fwrsQGn0doFDnELEJuGU2v2JEXA83TNVTXKQFcSKxdtRQ0rnZCh9QF4YMPh5Wqmcmq73emJGCPyV7NSLZqFNWSWcgwJAbU932BAL3oA--WDWa1nkSkztRVTNy_AGAxSqbX5dH0CEnMfPBFK8uftAIoJlH5CmQWnPrC0ULT9XApq7UZBvA8nSW9xfvdaU4ewvI_JhzI9W_5gzDWHXjwLUXvcwtaQ"
    }

获取到Refresh Token和Access Token后，会调用login接口：

    url:
    https://accounts.google.com/oauth/multilogin?source=ChromiumAccountReconcilor&reuseCookies=0

    request header:
    content-length: 1
    authorization: MultiBearer ya29.a0AVA9y1uiv6r13spjA0J7hfFFSSqZEC2OF94WZpEhhiQOZBVnZObBnFoyIqbS6npfC4510pnyMtoQAD5PvxPX23zMaIoZNZRhsS0zqRBPdotk-DlNnj9Hgn4XTMWrBDpDU87jeVNqgzhs9pAYo6RTKPrHK7Lmtj23sVkWoLmhKaqE8g3NzPtWLAc6WHVZPD0SfmC4mFhxfG3R6vUSAAAs8MHhyDsqYCSVxU9-hi1XKU3V2uRlUhf_HW-CuHYJsSTOWSoaCgYKATASAQASFQE65dr8g7foGT5XAGbIb1sxH8W8Cg0266:113934407622812037815
    content-type: application/x-www-form-urlencoded
    sec-fetch-site: none
    sec-fetch-mode: no-cors
    sec-fetch-dest: empty
    user-agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
    accept-encoding: gzip, deflate, br
    accept-language: en-US,en;q=0.9

    respone header:
    HTTP/1.1 200
    content-type: application/json; charset=utf-8
    x-frame-options: DENY
    vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site
    x-content-type-options: nosniff
    cache-control: no-cache, no-store, max-age=0, must-revalidate
    pragma: no-cache
    expires: Mon, 01 Jan 1990 00:00:00 GMT
    date: Mon, 05 Sep 2022 07:18:35 GMT
    content-disposition: attachment; filename="json.txt"; filename*=UTF-8''json.txt
    content-encoding: gzip
    strict-transport-security: max-age=31536000; includeSubDomains
    content-security-policy: require-trusted-types-for 'script';report-uri /cspreport
    content-security-policy: script-src 'report-sample' 'nonce-FAJz-vE6VSpijeWcsrBd5A' 'unsafe-inline' 'unsafe-eval';object-src 'none';base-uri 'self';report-uri /cspreport
    report-to: {"group":"coop_gse_qebhlk","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gse_qebhlk"}]}
    cross-origin-opener-policy-report-only: same-origin; report-to="coop_gse_qebhlk"
    x-xss-protection: 1; mode=block
    server: GSE
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

    data:
    {"status":"OK","cookies":[{"name":"SID","value":"OAiH8PvwOnrCZC9oU1v8CBTptY4QSC0lF4q4up9AczG46M1l8_TNTa59_B_zAElhpwgyEA.","domain":".google.com.tw","path":"/","isSecure":false,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH"},{"name":"__Secure-1PSID","value":"OAiH8PvwOnrCZC9oU1v8CBTptY4QSC0lF4q4up9AczG46M1l8hw3YrukgcV0LZfXs3ObWw.","domain":".google.com.tw","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH","sameParty":"1"},{"name":"__Secure-3PSID","value":"OAiH8PvwOnrCZC9oU1v8CBTptY4QSC0lF4q4up9AczG46M1lLiOe4-qH8vWlX8O_PaQ_kA.","domain":".google.com.tw","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH","sameSite":"none"},{"name":"HSID","value":"A_3K_bnc2MCJWdCS-","domain":".google.com.tw","path":"/","isSecure":false,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"},{"name":"SSID","value":"AnLRnxFehS3uJPj7V","domain":".google.com.tw","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"},{"name":"APISID","value":"ZA4ZhyLgkgYJMIzw/AVOkv-RYT9HPr6dS3","domain":".google.com.tw","path":"/","isSecure":false,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH"},{"name":"SAPISID","value":"G9x9S2MlIwtH2Xrn/AUnb2V7PiMT0-X1_K","domain":".google.com.tw","path":"/","isSecure":true,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH"},{"name":"__Secure-1PAPISID","value":"G9x9S2MlIwtH2Xrn/AUnb2V7PiMT0-X1_K","domain":".google.com.tw","path":"/","isSecure":true,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH","sameParty":"1"},{"name":"__Secure-3PAPISID","value":"G9x9S2MlIwtH2Xrn/AUnb2V7PiMT0-X1_K","domain":".google.com.tw","path":"/","isSecure":true,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH","sameSite":"none"},{"name":"SID","value":"OAiH8PvwOnrCZC9oU1v8CBTptY4QSC0lF4q4up9AczG46M1l8_TNTa59_B_zAElhpwgyEA.","domain":".google.com","path":"/","isSecure":false,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH"},{"name":"__Secure-1PSID","value":"OAiH8PvwOnrCZC9oU1v8CBTptY4QSC0lF4q4up9AczG46M1l8hw3YrukgcV0LZfXs3ObWw.","domain":".google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH","sameParty":"1"},{"name":"__Secure-3PSID","value":"OAiH8PvwOnrCZC9oU1v8CBTptY4QSC0lF4q4up9AczG46M1lLiOe4-qH8vWlX8O_PaQ_kA.","domain":".google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH","sameSite":"none"},{"name":"LSID","value":"s.TW:OAiH8JdC4jr-n7xoa9IeL1ucL2akKPvmdEsSsR6uq2qQvGcHnKQFpib3mqBA6syAYlF3hg.","host":"accounts.google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"},{"name":"__Host-1PLSID","value":"s.TW:OAiH8JdC4jr-n7xoa9IeL1ucL2akKPvmdEsSsR6uq2qQvGcHcnRUlOpiXkRIwXxWd3287w.","host":"accounts.google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH","sameParty":"1"},{"name":"__Host-3PLSID","value":"s.TW:OAiH8JdC4jr-n7xoa9IeL1ucL2akKPvmdEsSsR6uq2qQvGcHsGEUsZ4JucgRMegCVqKjkA.","host":"accounts.google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH","sameSite":"none"},{"name":"HSID","value":"AySgFfFluDbNtvu2O","domain":".google.com","path":"/","isSecure":false,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"},{"name":"SSID","value":"A3zusR8u0Qs4Z6DMm","domain":".google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"},{"name":"APISID","value":"ZA4ZhyLgkgYJMIzw/AVOkv-RYT9HPr6dS3","domain":".google.com","path":"/","isSecure":false,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH"},{"name":"SAPISID","value":"G9x9S2MlIwtH2Xrn/AUnb2V7PiMT0-X1_K","domain":".google.com","path":"/","isSecure":true,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH"},{"name":"__Secure-1PAPISID","value":"G9x9S2MlIwtH2Xrn/AUnb2V7PiMT0-X1_K","domain":".google.com","path":"/","isSecure":true,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH","sameParty":"1"},{"name":"__Secure-3PAPISID","value":"G9x9S2MlIwtH2Xrn/AUnb2V7PiMT0-X1_K","domain":".google.com","path":"/","isSecure":true,"isHttpOnly":false,"maxAge":63072000,"priority":"HIGH","sameSite":"none"},{"name":"ACCOUNT_CHOOSER","value":"AFx_qI7Sx5yu_TsT5ewLee25tmli3PbSZxSi_RLDQmfE2BDFvtplGt7dELrVUtFrRGWU1A2PD4Oql0_QfOkg_7bL4_m14j2hMqx073FJjgEGmmoEjNS0AupXx4q8YRP7Vc7l0Z4KAcdW","host":"accounts.google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"},{"name":"__Host-GAPS","value":"1:B8yvPEM62YCys_zPcrIPrGyXgsh72PRSNC_F8UEObw4ye5i9-Ge1e8-I2LJsk8lVtRu_87x15HWpo_SaA97pEvxiwiRW6g:Zk06H0KuDeqwd2a_","host":"accounts.google.com","path":"/","isSecure":true,"isHttpOnly":true,"maxAge":63072000,"priority":"HIGH"}],"accounts":[{"type":"PERSON_ACCOUNT","display_name":"Dao Ding","display_email":"pwaruntime@gmail.com","photo_url":"https://lh3.googleusercontent.com/-UCG1ush51EY/AAAAAAAAAAI/AAAAAAAAAAA/Pbv7BhdzzqI/s48-c/photo.jpg","selected":false,"default_user":true,"authuser":0,"valid_session":true,"obfuscated_id":"113934407622812037815","is_verified":true}]}

同时会获取一个Uber Token，

    url：
    https://accounts.google.com/OAuthLogin?source=ChromiumBrowser&issueuberauth=1

    request header:
    authorization: OAuth ya29.a0AVA9y1uW6qeiObanknnEcO93XR_GZZFKT98R_pZumRxdmqAn7Cui99rb0viiKJklot9TKCGNxiEFImeVZSuIA0pw7gxfo1RLXfvvcySCXV7QJCGSUkfQlZDB8lVjybH4QshV-dgeD1UCOoldjUENak-D8LoEcOWw6r23AHVMupz-XnfcvCQuLRPsypgoD-6iRlU6Dn4rBbSu7tWK-ZBwJaJI1lkIDwZdAqdnOD0cEeo1tExLiJqj4BdcWwx0gPx1Hk4aCgYKATASAQASFQE65dr8spZyuJGSCg1xdx2vblb0ww0266
    sec-fetch-site: none
    sec-fetch-mode: no-cors
    sec-fetch-dest: empty
    user-agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
    accept-encoding: gzip, deflate, br
    accept-language: en-US,en;q=0.9


    respone header:
    HTTP/1.1 200
    content-type: text/plain; charset=utf-8
    vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site
    google-accounts-programmatic-authenticated: 113934407622812037815
    cache-control: no-cache, no-store, max-age=0, must-revalidate
    pragma: no-cache
    expires: Mon, 01 Jan 1990 00:00:00 GMT
    date: Mon, 05 Sep 2022 07:18:35 GMT
    strict-transport-security: max-age=31536000; includeSubDomains
    permissions-policy: ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-platform=*, ch-ua-platform-version=*
    content-security-policy: script-src 'report-sample' 'nonce-3cR-yvsqf2NQuY34sUm4mA' 'unsafe-inline';object-src 'none';base-uri 'self';report-uri /_/IdentityAuthOAuthLoginHttp/cspreport;worker-src 'self'
    content-security-policy: script-src 'unsafe-inline' 'self' https://apis.google.com https://ssl.gstatic.com https://www.google.com https://www.gstatic.com https://www.google-analytics.com;report-uri /_/IdentityAuthOAuthLoginHttp/cspreport/allowlist
    content-security-policy: require-trusted-types-for 'script';report-uri /_/IdentityAuthOAuthLoginHttp/cspreport
    cross-origin-opener-policy: same-origin
    accept-ch: Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version
    content-encoding: gzip
    server: ESF
    x-xss-protection: 0
    x-frame-options: SAMEORIGIN
    x-content-type-options: nosniff
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

    data:
    APh-3FzAoqMaF3GArwTO0C2HylO8QjrC4P4oMEfieaT-VkVSb4HkuA1UfpkAdBraRvGhOztYU3GGPkHX7kIadCkHczhGu2Ur9WIvak-gZLdmqkqyFx9n9sUXRVAK5WysifhdObNUNpc2vmPwEhN0WJlbXuE5qb0N5X4aT8B3VkVh2C8EM1OrIUcu-UZw5LtYFUj64KJgPtV885ZA98v4mT3fky1PT9VozcIo3d4jlQsJBKGVmom-rCdJHPBJf9OeBDyAtNUndOFy8tzAzF29F_Oo9vBJtmzAMVifp5IcDbKli-0_PRIu5nPYlbu--KOmuEhczxvHD9df0e7fY_YgMvAM-hhx-M8wj8nd3dU8v2W6NQbyG9ImsdCWY1sxh_nXWpHdAb3ALxaGJ-yJuUsV2gAuYYAhTMFoViQezv5FN4K9ZOpWRgCPlZHbYx7Wvif5UaQUQ31FV8IE62UppWOCrU1V1L9kBFZ0PUKfNDLOkpVknCLAtrluatfURpqTJhZg0PS33_06rRmsm0USb0hclNThXXJ34GcOitaNpQysRrw1yYipoyhsJvnWXpKBOoz6qV2T-ExuONGzCiLDhAluT7W93jzFQgn11t7b6ysEs0sEb8P9jai5NDfixoESN6w0i1VL2Dx_903amLLRTQrTbDdvy_-vgNwhGA

获取到Uber Token后会调用合并接口将状态进行合并：

    url：
    https://accounts.google.com/MergeSession?uberauth=APh-3Fz83cJreRHcAjhJfaU_OVWheonAx7sPA0RRHWSQd0xoLx7yBWkccmh5nwmNqqyo-SFBAyBalOS30dpCHh4mPL82P2zJUJfJ5QTNc5HZozE8UC224aKKfWMVECPPctY1wCTsMyvox2-Veisa2FIk-H64kDsu2JM_BJvUSs9hJesb66SYktuz3sThk9BY5KIdVRtylHOkB8f201g49BD4iv4eg9AFlQ8Vpeshslj7Y9zv_r8ViSRmGwoVOjBJPhJoyuY7DJq27MrBrZqX9oaIf6Lv4Y9m3sX5NDl-g-fa_y6xrpX5HsZjO5tlN15zn0AlfPOFTE-T-pMII4zSGIKepzLshKKtCT0oZAagfQ01Ne00M2VJ1NgtzUmXLNH0ICNubch8-xHrZpOl-SPqx-tnszFaywSjTYpjgSOlYXefzaZ-kctDcHx8PWDR9KawUCO97Vf3SEw7DR4dBiECM0SStrrnJaaZg3-fWOKnuRC-ZN_8VBQSGODYXvU4rko4zT9gdnkJsyz-wz6iwnlx2JtL8858OZjZ0o-FpMh2YhUO0KyT25Ygp3UiZaPq6ViZOcZPsf1LPG7jV2D6_kjH5Ex7fuJYWwicAMDYWWG2EyaDb0W_b_88bwP9FLERNeJ7sdnbA7HFtw7QJIW2PmhOtPD3BJBGX0L_KA&continue=http://www.google.com&source=ChromiumOAuth2LoginVerifier

    request header:
    sec-fetch-site: none
    sec-fetch-mode: no-cors
    sec-fetch-dest: empty
    user-agent: Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36
    accept-encoding: gzip, deflate, br
    accept-language: en-US,en;q=0.9
    cookie: SID=OAiH8DQzmZxkLqXdX1k_9Wx0UJTmBy0bqubVnm3pjhN2QzNlmabSN4zb9sSh_tQuwIFDCw.; __Secure-1PSID=OAiH8DQzmZxkLqXdX1k_9Wx0UJTmBy0bqubVnm3pjhN2QzNlS9hvXQRcK9elcsPF625xLA.; __Secure-3PSID=OAiH8DQzmZxkLqXdX1k_9Wx0UJTmBy0bqubVnm3pjhN2QzNlM28wULfxuXmIVE1NWeyupg.; LSID=s.TW:OAiH8J4VvSn4EDjUsqnquNKfA5MCF8DkzvgfzduQEsXUC_uevlWBmlsZb7ecqUa2ueUlFw.; __Host-1PLSID=s.TW:OAiH8J4VvSn4EDjUsqnquNKfA5MCF8DkzvgfzduQEsXUC_ueVs-M5o73e32m-PZh01YtCA.; __Host-3PLSID=s.TW:OAiH8J4VvSn4EDjUsqnquNKfA5MCF8DkzvgfzduQEsXUC_ue7V4kCVZH80AXqxCAcmkmRw.; HSID=AbAdoqs0OOhl7YIYm; SSID=AYojqDxN5MH0ExAJX; APISID=3_HoGHwe1CEZY7Ko/Aiom175qDVN0W7ldP; SAPISID=tUXjaER0aoESj39T/AOfzNkF88WzwDzJgH; __Secure-1PAPISID=tUXjaER0aoESj39T/AOfzNkF88WzwDzJgH; __Secure-3PAPISID=tUXjaER0aoESj39T/AOfzNkF88WzwDzJgH; ACCOUNT_CHOOSER=AFx_qI738cAzfs_L64_YlAGdTfvqaNU1yg2iTSgIviJ0OWJIrtfS1-g7Eu9j-mH-VvTCD0U5XU8QTk6u4MZNk3trEYbyiPF0O1bRo9RUR_kTJRayy3rRqYU9NQdhvg3OZdocuvq6z9kH; __Host-GAPS=1:64Cbajs8e0AILO5Xr46mnWhygDy4zc4WEQYrdOnZTSSgD6PqRJQcFimmO69QfGd1REmxbOu9LUrAXdF3cb66RVI0UPJuPQ:X_QvcJc_qPeih-Er

    respone header:
    HTTP/1.1 302
    content-type: text/html; charset=UTF-8
    strict-transport-security: max-age=31536000; includeSubDomains
    x-frame-options: DENY
    content-security-policy: script-src 'report-sample' 'nonce-_mW6KiNNN84MM3HhbCCEFQ' 'unsafe-inline' 'unsafe-eval';object-src 'none';base-uri 'self';report-uri /cspreport
    p3p: CP="This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info."
    p3p: CP="This is not a P3P policy! See g.co/p3phelp for more info."
    cache-control: no-cache, no-store
    pragma: no-cache
    expires: Mon, 01-Jan-1990 00:00:00 GMT
    google-accounts-signin: email="pwaruntime@gmail.com", sessionindex=0, obfuscatedid="113934407622812037815"
    location: https://accounts.google.com/CheckCookie?continue=https%3A%2F%2Fwww.google.com&chtml=LoginDoneHtml&gidl=EgIIAA
    content-encoding: gzip
    date: Mon, 05 Sep 2022 07:18:35 GMT
    x-content-type-options: nosniff
    x-xss-protection: 1; mode=block
    content-length: 235
    server: GSE
    set-cookie: SID=OAiH8BJ3rfsB-Hj-6G-5wY6Ie2TzNEvEq2pH8lEvh89kQ8nQR6FfvG9cr9BgHTTCyC70hQ.;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Priority=HIGH
    set-cookie: __Secure-1PSID=OAiH8BJ3rfsB-Hj-6G-5wY6Ie2TzNEvEq2pH8lEvh89kQ8nQlst9imRAMAUvCVkoHpYMvw.;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH;SameParty
    set-cookie: __Secure-3PSID=OAiH8BJ3rfsB-Hj-6G-5wY6Ie2TzNEvEq2pH8lEvh89kQ8nQEPBoSoKLxaWfYJqyqR1UzQ.;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH;SameSite=none
    set-cookie: LSID=s.TW:OAiH8L9auyXUWCRdcdWalEXmxTlTImW0abakdI156tjKezAk_ocmhiNbsJtZRdje0tDLnw.;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH
    set-cookie: __Host-1PLSID=s.TW:OAiH8L9auyXUWCRdcdWalEXmxTlTImW0abakdI156tjKezAk4wdyro-KlyOUbiUFTSaDog.;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH;SameParty
    set-cookie: __Host-3PLSID=s.TW:OAiH8L9auyXUWCRdcdWalEXmxTlTImW0abakdI156tjKezAk3CAOUIXHAPom6Q5aBA-65Q.;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH;SameSite=none
    set-cookie: HSID=A3ntIJW_sru8YS-jm;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;HttpOnly;Priority=HIGH
    set-cookie: SSID=A1AX6jQ4wCyuN3upc;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH
    set-cookie: APISID=4Kl7g1DIP-RRqIji/Abe-SHHToZ0Z63Jnc;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Priority=HIGH
    set-cookie: SAPISID=lUSB4Dyf9Xe7HjcP/ApRW2vFt3iedliIS5;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;Priority=HIGH
    set-cookie: __Secure-1PAPISID=lUSB4Dyf9Xe7HjcP/ApRW2vFt3iedliIS5;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;Priority=HIGH;SameParty
    set-cookie: __Secure-3PAPISID=lUSB4Dyf9Xe7HjcP/ApRW2vFt3iedliIS5;Domain=.google.com;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;Priority=HIGH;SameSite=none
    set-cookie: __Host-GAPS=1:h_MvBwD5WuTYeNsPaHxja5BXOJO5cSHNXy7bXmQ3aMeS4ZyziHIU9gh1XFqsStUzsnc03xLfhyMs-TA75A2hocT2D79PwQ:l5FCuvH_XH-icQB_;Path=/;Expires=Wed, 04-Sep-2024 07:18:35 GMT;Secure;HttpOnly;Priority=HIGH
    set-cookie: NID=511=UM_n9ECvxtjjGj5EWtVK-LvAFIk36h8JlEuamgrF3sztNAAhJV4V3e0fCmfe7ovQthxX1sHRTlkKQftHCGFuJwjxwV73OCjU2rgC4saQ9jVCRQftQut5YafDPiOiRuG59GeGwXIKY7z8Y7AcildAeHJEh19y49MOv_IhDKuycRk34-RWSWqXjKnoIj0Nz_o; expires=Tue, 07-Mar-2023 07:18:35 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none
    set-cookie: SIDCC=AEf-XMRgE6e6ALOtT7VKV4CTCcFP_l_QZXv4Or-pKA5OFN6655ma0YXEzaujj0BFNw6Effq11A; expires=Tue, 05-Sep-2023 07:18:35 GMT; path=/; domain=.google.com; priority=high
    set-cookie: __Secure-1PSIDCC=AEf-XMSy_YML-IKAMGGLrFm0z8RVab9GMn9cYbCGscn_bQulEX7aNQGXX4YJhQ4aHfINDtib4w; expires=Tue, 05-Sep-2023 07:18:35 GMT; path=/; domain=.google.com; Secure; HttpOnly; priority=high
    set-cookie: __Secure-3PSIDCC=AEf-XMR6qOlFF5GgevuYzqUtz-dcyA7GStVxY6WcDAdxNO-54KfAlJyMv9NXH6LpD487i0Qt; expires=Tue, 05-Sep-2023 07:18:35 GMT; path=/; domain=.google.com; Secure; HttpOnly; priority=high; SameSite=none
    alt-svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

    data:
    <html><head><title>重新定向</title>

    <script type="text/javascript" language="javascript" nonce="iMGbHyglEI1yY6SdKbhjqQ">
          // Accessing window.external members can cause IE to throw exceptions.
          // Any code that acesses window.external members must be try/catch wrapped

          try {
            if (top == self) {
              if (window.gtbExternal) {
                window.gtbExternal.setM();
              } else {
                window.external.setM();
              }
            }
          }
          catch(err) {
          }
        </script>
    <script type="text/javascript" language="javascript" nonce="iMGbHyglEI1yY6SdKbhjqQ">
          // If the HTML5 History API is available, and we don't want some tokens in
          // the current url to be leaked into the Referer, update the current
          // history entry.
          if (!!(window.history && window.history.replaceState)) {

            try {
              window.history.replaceState(null, document.title,
                  "https://accounts.google.com/MergeSession");
            } catch (e) {
            }
          }
        </script>
    <meta http-equiv="refresh" content="0; url=&#39;http://www.google.com&#39;"></head>
    <body bgcolor="#ffffff" text="#000000" link="#0000cc" vlink="#551a8b" alink="#ff0000"><script type="text/javascript" language="javascript" nonce="iMGbHyglEI1yY6SdKbhjqQ">
        location.replace("http://www.google.com")
      </script></body></html>

这样账户在ChromeOS上登录成功，整个过程有两个登录，一个是browser正常的multilogin，一个是OS通知browser的UberToken，因此在最后有个MergeSession的请求。

#### &#x20;登录后会获取的Access Toke

    scopes:
    https://www.googleapis.com/auth/chromesync

    body：
    client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0eqpjG0Mpv5QLCgYIARAAGA4SNwF-L9Ir5fp58cX8nYb3E0yUkc4vXEt5u1Rnmx47eCk2TkJdgYyGSzgy4kspsnguj8G6WNcPjkU&scope=https://www.googleapis.com/auth/chromesync

    respone body:
    {
      "access_token": "ya29.a0AVA9y1vCDZdQ2_RovHSk5lQ7h54X6PNbvzBMMyTDCFcX3OGQWbtMZdykmK8DJjzYlH0c-y31ykqppEHxcvuqFdBvIbBfqx61IyLl56-8ExjR0WsbDyB7jamZU46EuqcU4jbB43SQICh9wkjxgQIEiE9OHmRISWzVC6h5x71B2f2A4tshJiw0owFizBy2rfHJBHCFqO6BLiKN_HQEkMTOBn_ZSoGpXlfuuNw3X8HbUP5s7jzjlsRZLSFxJp4qhAaimjXqES0aCgYKATASAQASFQE65dr8zr1aaOvMVJTEkJmvkZcEog0270",
      "expires_in": 73374,
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer"
    }



    scopes:
    https://www.googleapis.com/auth/account.capabilities

    body:
    client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0eqpjG0Mpv5QLCgYIARAAGA4SNwF-L9Ir5fp58cX8nYb3E0yUkc4vXEt5u1Rnmx47eCk2TkJdgYyGSzgy4kspsnguj8G6WNcPjkU&scope=https://www.googleapis.com/auth/account.capabilities

    response body:
    {
      "access_token": "ya29.a0AVA9y1tRedaGzjVUVO3e34_QsuYFAnXZGi6Yd1ckeC36thAWIWP2YG3vg2gIuRyUa-MlMw3QmS9prTZ8kBJyvSHR45I1VvtCDKEz8WAXxZsgIOHjQTwf1un1UB0AkBtBCDaVSKbR72TRIli6-0ERR8_qN69Z6JU7akekmA-burxFc4QGokwv0wuPiEUx78OGsLbkkpR3ciLsjec8n8ayFyUcZn4MQvzpIOap-OiE_V_mzK6TivMQeuxOtyjgeyGGfAaCgYKATASAQASFQE65dr8x30Z6LS4p0PiYJvezBQ0Zg0265",
      "expires_in": 3599,
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer"
    }

>     scopes:
>     https://www.googleapis.com/auth/userinfo.email
>     https://www.googleapis.com/auth/userinfo.profile
>
>     body:
>     client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0eqpjG0Mpv5QLCgYIARAAGA4SNwF-L9Ir5fp58cX8nYb3E0yUkc4vXEt5u1Rnmx47eCk2TkJdgYyGSzgy4kspsnguj8G6WNcPjkU&scope=https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile
>
>     respone body:
>     {
>       "access_token": "ya29.a0AVA9y1twXi3NPjW3sFu2xpwEEFZjx-KrvzyZ-dVxqotvRPsF8lyftu6qh4-IdFggy2Dd6RHuw9ZpemB-g29vaUve-hpSw83nq0-iux5NCzTcFGqq4IYr4uaJDq09siDOgBhRhtw7F6489yPKqXyuEwICNq5g5oUhg-7Klhmr4V4HuZ2_yOu-mzn16x8IZWPpyg64z8pC6K_8pw5U46pBEV2BaL3zj1V_juKm_XHgAcQphi4lxku_FJ15BVPseqkozwaCgYKATASAQASFQE65dr85_qHpHXXp2kNr0YMj-YXCw0265",
>       "expires_in": 3599,
>       "scope": "https://www.google.com/accounts/OAuthLogin",
>       "token_type": "Bearer",
>       "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU4NDdkOTk0OGU4NTQ1OTQ4ZmE4MTU3YjczZTkxNWM1NjczMDJkNGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3NzE4NTQyNTQzMC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6Ijc3MTg1NDI1NDMwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEzOTM0NDA3NjIyODEyMDM3ODE1IiwiZW1haWwiOiJwd2FydW50aW1lQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoidVB5VnZ2VkhfYjZiVDlWa29yb3FNZyIsIm5hbWUiOiJEYW8gRGluZyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BSXRidm1uNnNyaDlTOTdNcjlCM0dYQ3VTcGdvOE1xNlRnb2EwMUNrX2pVXz1zOTYtYyIsImdpdmVuX25hbWUiOiJEYW8iLCJmYW1pbHlfbmFtZSI6IkRpbmciLCJsb2NhbGUiOiJ6aC1DTiIsImlhdCI6MTY2MjQ1MTUyMSwiZXhwIjoxNjYyNDU1MTIxfQ.i3mV3jHto5DhUy8BhVQPYmi1hTFVtPd1yidRXFzmPpugP03Nc8yYtHVrCaizwXBfzfcNpKy17df-YR8H10WtCplicqzfuej1eS1A-wCfREpwXQRkzZ8timSD2nGUPYgdSvGtYg36CcOQ6_4UKXKs3aK1nAxD0pEnkXhhyGcWcSvxj9rqhLaE0-QvHerH9_IqTKNCfkN54GN4cV6OPkDLKAcV4QnwNJ4ttnGNWevDdU7uWETLJNCxX0jmVN3xGievP0-5vnEtW4J474qgFcTDEatWYp8bKiztidiuYssPmiIJCxQobTZZaPUNJb5YxiDNRQjixOiGD_4LK9QxDrbRRw"
>     }

    scopes:
    https://www.googleapis.com/auth/cryptauth

    body:
    client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0eqpjG0Mpv5QLCgYIARAAGA4SNwF-L9Ir5fp58cX8nYb3E0yUkc4vXEt5u1Rnmx47eCk2TkJdgYyGSzgy4kspsnguj8G6WNcPjkU&scope=https://www.googleapis.com/auth/cryptauth

    response body:
    {
      "access_token": "ya29.a0AVA9y1sxmYsJ7elwemEuSBK0ITQ2ChcgXsSaDG9ErA3Trs9IaPBHDrGnL3gE6kBvLnfXbL2nXLKHCxA_84jb1T74HXgGOQx4WnSS8V4vhlcxeAtvnmqow7yiAclJzvGdU5PzaqkzojqGPJENa2Q1oLIxJohKfX_R790CHvL2HcV5p04E5v5RZ5l19_-GTcs-Wo6GwMgslzo6NQHgabygAnWY4pM_rQLaniBa45cEEsfnswPbnnYmNhsW6hYC0UugkAaCgYKATASAQASFQE65dr8U2G1t_lj8oYm7aL5HZxfrg0265",
      "expires_in": 3599,
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer"
    }



    scopes:
    https://www.googleapis.com/auth/assistant-sdk-prototype
    https://www.googleapis.com/auth/gcm

    body:
    client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0ek7-Ps_SwU9oCgYIARAAGA4SNwF-L9IrfU2o-yvnpAunXqnrSQeyh1vjxKwqrsKut_nJ6rOa9N2aDisySuzZ3n9yIes-C_LFTP8&scope=https://www.googleapis.com/auth/assistant-sdk-prototype+https://www.googleapis.com/auth/gcm

    respones body:
    {
      "access_token": "ya29.a0AVA9y1tAC3F6_Qh5mchWQQPOQjFFIzrWuN1k5bJ6X_H7hJoHcVupQzzt72wudquiT1NRZiDiRfY7bIg_ObYeNayNrpydINQnZc3-x5cR06QNyxsJ1W4_B7UUlvXbq35iHuov_OH8rIQrDlEvu9-RbPO_hNS5CuZA8OomE-AB5YMQwX0hoeQPa5Ar0tFYrK_yH8NAvUZiTnw9k0aQW24kWwwzamtaoIKqZIFCIG5IrrCC5ZREfpOUMwSPRr_tZ3V5UhkaCgYKATASAQASFQE65dr8d4ORJdi5n9TkGe49B3iKKA0266",
      "expires_in": 3599,
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer"
    }



    scopes:
    https://www.googleapis.com/auth/android_checkin
    https://www.googleapis.com/auth/gcm

    body:
    client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0ek7-Ps_SwU9oCgYIARAAGA4SNwF-L9IrfU2o-yvnpAunXqnrSQeyh1vjxKwqrsKut_nJ6rOa9N2aDisySuzZ3n9yIes-C_LFTP8&scope=https://www.googleapis.com/auth/android_checkin+https://www.googleapis.com/auth/gcm

    response body:
    {
      "access_token": "ya29.a0AVA9y1uuT5ZsbE6RCeovW8zRaam7jJgpGgb0huKDuHbrLYYLVGGONPbUo54MzjR2c2z5Vp6EKz7Xos4GOWMk0yBDdAk3emNKz9ef9yMBvi0fAHH8urDC9SbJQQDz-Wb_0yG5-mnO_aBVNOgd0nAPW2XQTYT-Wc-YzaeafVdEOjX8y_Wr1_w1OaG4NiKoRmQWPp1v0FTOu0hN3pECEHccNPbZRTCk4zH5zxNXqMIL8skFgAssWJGMf8rrDmIyRlAhXfAaCgYKATASAQASFQE65dr8PbXHXkB0qgpQWSV2iMwiqQ0266",
      "expires_in": 3599,
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer"
    }



    scopes:
    https://www.google.com/accounts/OAuthLogin

    body:
    client_id=77185425430.apps.googleusercontent.com&client_secret=OTJgUOQcT7lO7GsGZq2G4IlT&grant_type=refresh_token&refresh_token=1//0ek7-Ps_SwU9oCgYIARAAGA4SNwF-L9IrfU2o-yvnpAunXqnrSQeyh1vjxKwqrsKut_nJ6rOa9N2aDisySuzZ3n9yIes-C_LFTP8&scope=https://www.google.com/accounts/OAuthLogin

    respons body:
    {
      "access_token": "ya29.a0AVA9y1tLVamddlYmMFm-LWMpAFWAG33qy2sv80GR83m2Nnxb10KuY5_M6k15MNqi5r8J-PrE09hwyX297tIhUMojvIwedQ9nc6lGTN_gzJknQ9ZhVNtfLHZzizvTEhSC7OyAcvmrIRXb387_kfb3475DVEpXZR1Eua-qowSHBXP_mEXfB20LKnnEtvKWmgwLFhu9uHr04cYwRL8xnXklWV9LZIoNcEzoiry63W48ITfMFvLcHhtMbUYpRFebTD7xHlMaCgYKATASAQASFQE65dr8TXOZcP9CIWhz3fAT8abeew0266",
      "expires_in": 64928,
      "scope": "https://www.google.com/accounts/OAuthLogin",
      "token_type": "Bearer",
      "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU4NDdkOTk0OGU4NTQ1OTQ4ZmE4MTU3YjczZTkxNWM1NjczMDJkNGUiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI3NzE4NTQyNTQzMC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6Ijc3MTg1NDI1NDMwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTEzOTM0NDA3NjIyODEyMDM3ODE1IiwiZW1haWwiOiJwd2FydW50aW1lQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiRURNcXAyWFJRbjh3c2ZUcmNSaDhCdyIsInNlcnZpY2VzIjpbXSwiaWF0IjoxNjYyNDUyMjM0LCJleHAiOjE2NjI0NTU4MzR9.QYzDj5y8uZUzADOkwmH7VnX-XBKJEtIlKpO3HrfObnqy-fZIUf9S9in0SFqU0pP1CPmTIuQ2GnlVJrTeoyjNStbh2x1eHhkcOh5UNgAVVlRJJQil98PaTZ-DJPoXgSYyLF4DqMFc20NiwQUVvnMZQDc_xs6gHjGKN_oZJxkf8-xWswKwsemW32Hv6QQHEjaWWATNvbb_9xirsLCBLrAm1uUsKzmyo7bMS3KaTLYAOOEKtZ-hg-9HW63I-r7Pe_UYYPn5quDrmhLvBPNpZtHfhCPW0Vn4JWi5lg1cI3vWIGQdtlIXr7q3jnvBy3M8ZK8V0AgwxXrM87J7oD1909t54w"
    }

scope为https\://www\.google.com/accounts/OAuthLogin的Access Token是请求MultiLogin时需要的。

#### &#x20;Uber Token的使用

ChromeOS登录后会通过auth code获取Refresh Token和Access Token，然后获取user info并保存到用户上下文中，当chromium打开登录时，首先通过已经登录的账户中获取Access Token，然后调用MultiLogin请求进行登录，同时ChromeOS也会主动将同一账户添加到chromium中，这个添加行为会调用获取Uber Token请求，然后调用MergeSession请求。整个过程相当于将ChromeOS的账户与Chromium的账户进行合并。
