# 스프링 시큐리티 개념 및 구조 이해
- `SecurityBuilder`는 웹 보안을 구성하는 빈(Bean) 객체와 설정 클래스들을 생성하는 역할
  - `WebSecurity`, `HttpSecurity`가 있다.
- `SecurityConfigurer`는 Http 요청과 관련된 보안처리를 담당하는 필터들을 생성하고 여러 초기화 설정에 관여
- `SecurityBuilder`는 `SecurityConfigurer`를 포함하고 있으며 인증 및 인가 초기화 작업은 `SecurityConfigurer`에 의해 진행된다.

```mermaid
    flowchart LR
    0[AutoConfiguration] -->|"build()"| A[SecurityBuilder]
    A[SecurityBuilder] -->|"init() & configure()"| B(SecurityConfigurer)
    B(SecurityConfigurer) --> C[초기화 설정 작업]
    A --> |build| Z[SecurityFilterChain]
    WebSecurity -.-> A
    HttpSecurity -.-> A
    LogoutConfigurer -.-> B
    CsrfConfigurer -.-> B
    SessionManagementConfigurer -.-> B
    ... -.-> B
```

실제 자동구성은 다음과 같다.

`SpringWebMvcImportSelector` ➡ `SecurityFilterAutoConfiguration` ➡ `WebMvcSecurityConfiguration` ➡ `HttpSecurityConfiguration`

### 설정하지 않은 SecurityFilterChain이 자동으로 등록되는 이유
```java
@Configuration(proxyBeanMethods = false)
@ConditionalOnDefaultWebSecurity // <<<
static class SecurityFilterChainConfiguration {

    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }
}
```
`defaultSecurityFilterChain`이 동작하기 위해서는 `ConditionalOnDefaultWebSecurity` 조건이 필요하다.

```java
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Conditional(DefaultWebSecurityCondition.class) // <<<
public @interface ConditionalOnDefaultWebSecurity {
}
```
`ConditionalOnDefaultWebSecurity` 어노테이션을 보면 `DefaultWebSecurityCondition` 조건을 걸고있는 것을 확인할 수 있다.

`DefaultWebSecurityCondition` 클래스를 확인해 보자

```java
class DefaultWebSecurityCondition extends AllNestedConditions {

  DefaultWebSecurityCondition() {
    super(ConfigurationPhase.REGISTER_BEAN);
  }

  @ConditionalOnClass({ SecurityFilterChain.class, HttpSecurity.class })
  static class Classes {
  }

  @ConditionalOnMissingBean({ SecurityFilterChain.class }) // <<<
  static class Beans {
  }
}
```
사용자가 `SecurityFilterChain`을 빈으로 등록하지 않으면 위 조건이 모두 만족하므로

결과적으로 `defaultSecurityFilterChain`이 동작하며 기본 빈이 생성되는 것이다.

## AuthenticationEntryPoint 이해

인증 및 인가 처리 과정에서 예외가 발생한 경우 예외를 핸들링하는 인터페이스이다.

직접 정의한 `AuthenticationEntryPoint`를 빈으로 등록하지 않으면 

인증 방식(form, basic, ...)에 따른 `AuthenticationEntryPoint`가 동작하게 된다.

## CORS(Cross-Origin Resource Sharing, 교차 출처 리소스 공유)
- HTTP 헤더를 사용하여 한 출처에서 실행 중인 웹 애플리케이션이 다른 출처에 접근할 수 있는 권한을 부여하도록 브라우저에게 알려주는 체제
- 웹 애플리케이션이 리소스가 자신의 출처와 다를 때 브라우저는 요청 헤더에 Origin 필드에 요청 출처를 함께 담아 교차 출처 HTTP 요청을 실행
- 출처를 비교하는 로직은 브라우저에 구현된 스펙 기준으로 처리
  - Protocol, Host, Port 이 세가지가 동일한지 확인

### Simple Request
예비 요청(Preflight) 과정 없이 바로 서버에 본 요청을 한 후, 서버가 응답 헤더에 `Access-Control-Allow-Origin`과 같은 값을 전송하면 브라우저가 서로 비교 후 CORS 정책 위반여부를 검사하는 방식
- `GET`, `POST`, `HEAD` 중 한가지 Method만 사용 가능
- `Content-type`은 `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`만 가능하다.
### Preflight Request(예비 요청)
요청을 한번에 보내지 않고, 예비 요청과 본 요청으로 나누어 서버에 전달하는데 브라우저가 예비 요청을 보내는 것을 Preflight라고 하며 이 예비 요청의 메서드는 `OPTIONS`가 사용된다.
- 요청 사양이 Simple Request에 해당하지 않을 경우 Preflight Request를 실행한다.

### CORS 해결
- Access-Control-Allow-Origin: 헤더에 작성된 출처만 브라우저가 리소스를 접근할 수 있도록 허용
  - `*`, `https://noose.com`
- Access-Control-Allow-Methods: preflight request에 대한 응답으로 실제 요청 중에 사용할 수 있는 메서드를 나타냄
- Access-Control-Allow-Headers: preflight request에 대한 응답으로 실제 요청 중에 사용할 수 있는 헤더 필들 이름을 나타냄
- Access-Control-Allow-Credentials: 실제 요청에 쿠키나 인증 등의 사용자 자격 증명이 포함될 수 있음을 나타낸다.
- Access-Control-Max-Age: preflight 요청 결과를 캐시 할 수 있는 시간을 나타냄

#### Spring Security에서 사용하는 방법
- FilterChain에 CorsFilter를 추가
- corsFilter 라는 이름의 빈이 제공되면 해당 CorsFilter가 사용됨
- corsFilter 라는 이름의 빈이 없고 CorsConfigurationSource 빈이 정의된 경우 해당 CorsConfiguration이 사용됨

> **CorsFilter**
> 
> CORS 예비 요청과 단순 및 본 요청을 가로채고, 제공된 CorsConfigurationSource를 통해 일치된 정책에 따라 CORS 응답 헤더와 같은 응답을 업데이트하기 위한 필터 

---

# OAuth2
**OAuth** = **Open** + **Auth**orization

- OAuth 2.0 인가 프레임워크는 애플리케이션이 사용자를 대신하여 사용자의 자원에 대한 제한된 액세스를 얻기 위해 승인 상호 작용을 함으로써 애플리케이션이 자체적으로 액세스 권한을 얻도록 한다.
- 사용자가 속한 사이트의 보호된 자원에 대하여 애플리케이션의 접근을 허용하도록 승인하는 것을 의미
```mermaid
sequenceDiagram
    autonumber
    Actor O as Resource Owner
    participant C as Client
    participant S as Authorization & Resource Server

    O->>C: 서비스 이용(Resource) 요청
    C->>S: Resource 액세스 요청 (권한부여 코드 요청)
    S-->>O: 로그인 페이지
    O->>S: 로그인
    S-->>O: 로그인 성공(Consent) 후 Redirect with code
    O->>C: Redirect with code
    C->>S: Code를 사용하여 Access Token 요청
    S->>S: code 검증
    S-->>C: Resource에 접근이 가능한 Access Token 발급
    C->>S: Access Token을 사용해서 Resource 요청
    S->>S: access token 검증
    S-->>C: Resource
    C-->>O: Resource
```

## OAuth 2.0 Rolse
다음 4가지 종류의 역할을 담당하는 주체들에 의해 이루어지는 권한부여 체계
1. Resource Owner (자원 소유자)
   - 보호된 자원에 대한 접근 권한을 부여할 수 있는 주체, 사용자로서 계정의 일부에 대한 접근 권한을 부여하는 사람
   - 사용자를 대신하여 작동하려는 모든 클라이언트는 먼저 사용자의 허가를 받아야한다.
1. Resource Server (보호 자원서버)
   - 타사 애플리케이션에서 접근하는 사용자의 자원이 포함된 서버를 의미
   - 액세스 토큰을 수락 및 검증할 수 있어야 하며 권한 체계에 따라 요청을 승인할 수 있어야 한다.
1. Authorization Server (인가 서버)
   - 클라이언트가 사용자 계정에 대한 동의 및 접근을 요청할 때 상호 작용하는 서버로서 클라이언트의 권한 부여 요청을 승인하거나 거부하는 서버
   - 사용자가 클라이언트에게 권한 부여 요청을 승인한 후 access token을 클라이언트에게 부여하는 역할
   - ex) Keycloak, Spring Authorization Server, Okta
1. Client (클라이언트)
   - 사용자를 대신하여 권한을 부여받아 사용자의 리소스에 접근하려는 애플리케이션
   - 사용자를 권한 부여 서버로 안내하거나 사용자의 상호 작용 없이 권한 부여 서버로부터 직접 권한을 얻을 수 있다.

## Keycloak
ID 및 접근 관리를 지원하는 인가서버 오픈 소스로 사용자 연합, 강력한 인증, 사용자 관리, 세분화된 권한 부여 등을 제공
- 해당 프로젝트에서 OAuth2 실습 시 인가 서버 목적으로 사용
- [다운로드](https://www.keycloak.org/downloads)

```bash
# 공개 클라이언트 (Implicit Flow 활성화)
curl --location --request GET "http://$KEYCLOAK_ADDRESS/realms/$REALM/protocol/openid-connect/auth?response_type=token&client_id=$CLIENT_ID&scope=profile%20email&redirect_uri=$CLIENT_ADDRESS"


# 리소스 요청을 위한 인증 및 코드 요청 - 기밀 클라언트
curl --location --request GET "http://$KEYCLOAK_ADDRESS/realms/$REALM/protocol/openid-connect/auth?response_type=code&client_id=$CLIENT_ID&scope=profile%20email&redirect_uri=$CLIENT_ADDRESS"

# 해당 코드를 사용하여 토큰 요청 - 기밀 클라언트
curl --location --request POST "http://$KEYCLOAK_ADDRESS/realms/$REALM/protocol/openid-connect/token" \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode "client_id=$CLIENT_ID" \
--data-urlencode "client_secret=$CLIENT_SECRET" \
--data-urlencode "redirect_uri=$CLIENT_ADDRESS" \
--data-urlencode "code=$CODE"

# 토큰을 사용하여 리소스 요청 - 기밀 클라언트
curl --location --request GET "http://$KEYCLOAK_ADDRESS/realms/$REALM/protocol/openid-connect/userinfo" \
--header "Authorization: Bearer $ACCESS_TOKEN"
```

## OAuth 2.0 Client Types
- 인증 서버에 클라이언트를 등록할 때 클라이언트 자격 증명인 클라이언트 아이디와 암호를 받는다.
- 클라이언트 암호는 비밀이고 그대로 유지되어야 하는 반면 클라이언트 아이디는 공개이다.
- 이 자격 증명은 인증 서버에 대한 클라이언트 ID를 증명한다.

### 공개 클라이언트 (Public Clients)
- 공개 클라이언트는 client_secret의 기밀을 유지할 수 없으므로 이러한 앱에는 secret이 사용되지 않는다.
  - 브라우저(SPA)에서 실행되는 JavaScript 애플리케이션, Android 또는 IOS 모바일 앱, 데스크톱에서 실행되는 기본 앱, IoT/임베디드 장치에서 실행되는 애플리케이션 등
  - 개발자 도구나 디버깅 도구를 사용하여 바이너리/실행 코드에서 기밀 정보룰 추출할 수 있음
  - 서버측이 아닌 리소스 소유자가 사용하는 장치에서 실행되는 모든 클라이언트는 공개 클라이언트로 간주되어야 함
```mermaid
sequenceDiagram
    title Public
    autonumber
    participant C as Client
    participant S as Authorization Server

    rect rgb(255, 223, 255)
    note over C, S: front channel
    C->>S: request authorization
    S-->>C: access token
    end
    rect rgb(180, 223, 255)
    note over C, S: back channel
    end
```

### 기밀 클라이언트 (Confidential Clients)
- 기밀 클라이언트는 client_secret의 기밀성을 유지할 수 있는 클라이언트를 의미
  - 일반적으로 사용자가 소스 코드에 액세스할 수 없는 서버에서 실행되는 응용 프로그램으로 Java, PHP 및 Node.js 같은 서버 측 언어로 작성
  - 이러한 유형의 애플리케이션은 대부분 웹 서버에서 실행되기 때문에 일반적으로 `웹 앱`이라고 한다.
```mermaid
sequenceDiagram
    title Confidential
    autonumber
    participant C as Client
    participant S as Authorization Server

    rect rgb(255, 223, 255)
    note over C, S: front channel
    C->>+S: request authorization
    S-->>C: redirect with code
    end
    rect rgb(180, 223, 255)
    note over C, S: back channel
    C->>S: send code
    S-->>C: access token
    end
```

## OAuth 2.0 Token Types
1. Access Token
    - 클라이언트에서 사용자의 **보호된 리소스에 접근하기 위해 사용하는 일종의 자격 증명**으로서 역할을 하며 리소스 소유자가 클라이언트에게 부여한 권한
    - 일반적으로 JWT 형식을 취하지만 사양에 따라 그럴 필요는 없다.
    - 토큰에는 해당 엑세스 기간, 범위 및 서버에 필요한 기타 정보가 있다.
    - 타입에는 *식별자* *타입*(Identifier Type)과 *자체* *포함타입*(Self-contained Type)이 있다.
1. Refresh Token
   - **액세스 토큰이 만료된 후 새 엑세스 토큰을 얻기 위해 클라이언트 응용 프로그램에서 사용하는 자격 증명**
   - 액세스 토큰이 만료되는 경우 클라이언트는 권한 부여 서버로 인증하고 Refresh Token을 전달한다.
   - 인증 서버는 Refresh Token의 유효성을 검사하고 새 액세스 토큰을 발급한다.
   - Refresh Token은 액세스 토큰과 달리 권한 서버 토큰 엔드포인트에만 보내지고 리소스 서버에는 보내지 않는다.
1. ID Token
   - OpenID connect
1. Authorization Code
   - **권한 부여 코드 흐름에서 사용**
   - **클라이언트가 액세스 토큰과 교환할 임시 코드**
   - 인가 서버로부터 리다이렉트 되어 받아온다.


**식별자 타입**

| access token     | username | scope              | expires_in |
|------------------|----------|--------------------|------------|
| dor27tptmxhzms77 | noose    | email, read, write | 123456789  |
| ...              | ...      | ...                | ...        |

**자체 포함 타입**
- JWT
  - 특정 암호화 알고리즘을 사용하여 개인키로 서명되고 공개키로 검증할 수 있으며 만료될 때까지 유효

## OAuth 2.0 Grant Types
권한 부여란 클라이언트가 사용자를 대신해서 사용자의 승인하에 인가서버로부터 권한을 부여받는 것

- Authorization Code Grant Type
  - 서버 사이드 애플리케이션
  - 보안에 가장 안전한 유형
- Implicit Grant Type **(Deprecated)**
  - 공개 클라이언트 애플리케이션에서 사용
  - 토큰이 브라우저에 노출 ➡ 보안에 취약
- Resource Owner Password Credentials Grant Type **(Deprecated)**
  - 리소스 사용자 비밀번호 자격증명 부여 타입
  - 클라이언트가 사용자의 자격증명을 모두 읽을 수 있음
- Client Credentials Grant Type
  - Secret 값만 있다면 인증이 가능
  - 화면이 없는 서버 애플리케이션 (데몬)
- Refresh Token Grant TYpe
- PKCE-enhanced Authorization Code Grant Type
  - Authorization Code Grant Type에서 파라미터가 추가됨
    - 값은 해시된 데이터

### 매개 변수 용어
- `client_id`: 인가 서버에 등록된 클라이언트에 대해 생성된 고유 키
- `client_secret`: 인가 서버에 등록된 특정 클라이언트의 client_id에 대해 생성된 비밀 값
- `response_type`
  - 애플리케이션이 권한 부여 코드 흐름을 시작하고 있음을 인증 서버에 알려준다.
  - code, token, id_token이 있으며 token, id_token은 implict 권한 부여 유형에서 지원해야함
  - 서버가 query string에 인증 코드(code), 토큰(token, id_token) 등을 반환
- `grant_type`: 권한 부여 타입 지정
  - authorization_code
  - password
  - client_credentials
  - refresh_token
- `redirect_uri`
  - 사용자가 성공적으로 승인되면 권한 부여 서버가 사용자를 다시 응용 프로그램으로 리다이렉션
  - 토큰 요청의 redirect_uri는 인증 코드를 생성할 때 사용된 redirect_uri와 정확히 일치해야 한다.
- `scope`
  - 애플리케이션이 사용자 데이터에 접근하는 것을 제한하기 위해 사용됨
  - 사용자에 의해 특정 스코프로 제한된 권한 인가권을 발행함으로써 데이터 접근을 제한
- `state`
  - 응용 프로그은 임의의 문자열을 생성하고 요청에 포함하고 사용자가 앱을 승인한 후 서버로부터 동일한 값이 반환되는지 확인해야 함
  - 이것은 CSRF 공격을 방지하는 데 사용

## Authorization Code Grant
1. 사용자가 애플리케이션을 승인하면 인가서버는 Redirect URI로 임시 코드를 담아서 애플리케이션으로 다시 리다이렉트한다.
2. 애플리케이션은 해당 임시 코드를 인가서버로 전달하고 액세스 토큰으로 교환한다.
3. 애플리케이션이 액세스 토큰을 요청할 때 요청을 클라이언트 암호로 인증할 수 있으므로 공격자가 인증 코드를 가로채서 스스로 사용할 위험이 줄어듬
4. 액세스 토큰이 사용자 또는 브라우저에 표시되지 않고 애플리케이션에 다시 전달하는 가장 안전한 방법이므로 토큰이 다른 사람에게 누출된 위험이 줄어듬

- 권한 부여 코드 요청 시 매개변수
  - response_type=code (필수)
  - client_id (필수)
  - redirect_uri (선택)
  - scope (선택)
  - state (선택)
- 액세스 토큰 교환 요청 시 매개변수
  - grant_type=authorization_code (필수)
  - code (필수)
  - redirect_uri (필수)
  - client_id (필수)
  - client_secret (필수)
