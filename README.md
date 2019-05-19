---
layout: post
title: "[SPRING] Spring Security 사용하기"
---

spring boot 와 spring security 로 빠른 로그인 시스템을 만들어보자

# Step - 1 프로젝트 생성

spring initializr 공식 홈페이로 가서 기본적인 설정 후 패키지를 다운받자.

[https://start.spring.io/](https://start.spring.io/)

![spring security with package](/images/2019-5-15/spring-security-with-boot-1.png)

내가 받은 패키지는 아래와 같다.

- security (security 를 쓸거니...)
- jpa (빠른 개발에 좋다.. 자세한 내용은 생략)
- web (Web 프로젝트이니, web 이 있어야한다.)
- Thymeleaf (jsp, velocity 같은 뷰 템플릿이다.)
- h2 (mysql 대신에 h2 database 를 사용한다.)
- jdbc (spring datasource 를 연결하기 위해 사용한다.)
- Lombok (Getter, Setter 등 어노테이션으로 편리하게 하기위해 쓴다..)

하단에 Generate Project 부분을 클릭후 적당한 폴더에 압출 파일을 풀고 해당 프로젝트를 연다.

이제 프로젝트를 구동시킨 후 [http://127.0.0.1:8080](http://127.0.0.1:8080) 으로 접속하면 기본으로 제공 해 주는 로그인 페이지가 나온다.

![spring security](/images/2019-5-15/spring-security-2.png);

일단 설정 한게 없으니 다음으로 넘어가자

# Step - 2 config class 만들기

WebSecurityConfig class 를 만들자

```java
package ziponia.spring.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
    }
}

```

@Configuarion 어노테이션과 @EnableWebSecurity 어노테이션을 주입해주고, WebSecurityConfigurerAdapter class 를 상속받는다.

그럼 우리 입맛대로 security 를 제어 할 수 있다.

override class 를 차례대로 간편하게 살펴보자. 내가 이해한 대로 해석했으니, 이해가 안된다거나, 의문이 있다면 [시큐리티 공식 문서](https://docs.spring.io/spring-security/site/docs/5.2.0.BUILD-SNAPSHOT/reference/htmlsingle/) 를 살펴 보도록 하자

_AuthenticationManagerBuilder_

유저 인증정보를 설정 할 수 있다.

이곳에서, jdbc 에 인증정보를 연결하자.

_WebSecurity_

security 전역 설정을 할 수 있다. 밑에 HttpSecurity 보다 우선시 되며, static 파일 (css, js 같은) 인증이 필요없는 리소스는 이곳에서 설정 할 수 있다.

참고로, 나중에 이야기 할 security expression 중 `permitAll()` 은 누구든 허용 한 다는 뜻이지, 시큐리티에서 제외한다는 뜻은 아니다. '제외' 와 '허용' 은 다르다.

_HttpSecurity_

가장 많이 설정 하게 될, 리소스 보안 부분이다. 여기에 대해선 차근차근 살펴보도록하자.

# Step - 3 config 설정

먼저 PasswordEncoder 를 설정하자. Spring boot 는 PasswordEncoder 를 설정 해 주지않으며, 이부분은 개발자가 직접 등록 해야한다. 등록하지 않으면

`java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"`

에러가 난다.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //...

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
```

이제 유저를 생성하자.

configure 메서드 중 AuthenticationManagerBuilder 를 오버라이드 한 메서드를 찾아서 아래와 같이 변경하자.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //...

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user") // user 계정을 생성했다. 이부분에 로그인아이디가 된다.
                .password(passwordEncoder().encode("1234")) // passwordEncoder 로 등록 한 인코더로 1234 를 암호화한다.
                .roles("USER"); // 유저에게 USER 라는 역할을 제공한다.
    }

    //...
}

```

이제 다시 접속하여, user 와 1234 를 입력하여 404 not found 가 뜨면 성공이다.

# Step - 4 Page 권한 부여하기

security 를 이용하여, 페이지 별로 권한을 부여 해보자.

먼저 페이지를 띄워야 하니, Controller 를 생성하자.

```java
package ziponia.spring.security;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SecurityController {

    @GetMapping(value = "/")
    public String home() {
        return "index";
    }

    @GetMapping(value = "/private")
    public String privatePage() {
        return "private";
    }

    @GetMapping(value = "/public")
    public String publicPage() {
        return "public";
    }
}

```

단순하게 / , /private, /public 페이지를 만들었다.

이제 view 를 생성하자.

```
src
    /main
        /resources
            /templates
                /index.html
                /private.html
                /public.html
```

세가지 view 파일을 만들고, 내용은 각각 index, private, public 이라고만 작성하였다.

이제 페이지별로 역할을 주기위해, WebSecurityConfig class 에 HttpSecurity 설정을 찾아 아래와 같이 수정 해보자.

```java

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //...

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http // HttpSecurity 객체를 설정한다.
                .authorizeRequests() // 권한요청 처리 설정 메서드이다.
                .antMatchers("/private/**").hasAnyRole("USER") // /private 이하의 모든 요청은 USER 역할이 있어야한다.
                .anyRequest().permitAll() // 다른 요청은 누구든지 접근 할 수 있다.
        .and()
            .formLogin(); // 로그인 form 을 사용한다.
    }

    //...
}
```

이제 어플리케이션을 재부팅 후, [http://127.0.0.1:8080/](http://127.0.0.1:8080/) 경로로 접근 해 보자.

정상적으로 index 내용이 나올 것이다.

그다음 [http://127.0.0.1:8080/private](http://127.0.0.1:8080/private) 로 접근해 보자.

로그인 화면으로 리다이렉트 될꺼고, 아이디와 비밀번호를 입력하면 private 내용을 볼 수 있다.

# Step - 5 로그인 폼 커스텀 하기

시큐리티에서 제공하는 로그인 폼을 커스터마이징 해보자.

커스텀이라기보다는 그냥 새로 만드는 것이다.

templates 폴더에 login.html 을 만들자

_login.html_

```html
<!DOCTYPE html>
<html lang="ko" xmlns:th="http://www.thymeleaf.org">
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0"
    />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <title>Document</title>
  </head>
  <body>
    <fieldset>
      <legend>로그인</legend>
      <form th:action="@{/login}" th:method="post">
        <input type="text" name="username" placeholder="아이디를 입력 해 주세요." />
        <br />
        <input type="password" name="password" placeholder="비밀번호를 입력 해 주세요." />
        <br />
        <button type="submit">로그인</button>
      </form>
    </fieldset>
  </body>
</html>
```

그 다음, 컨트롤러에서 /login 경로가 login.html 을 랜더링 할 수 있도록 만들어주자.

```java
@Controller
public class SecurityController {

    //...

    @GetMapping(value = "/login")
    public String loginPage() {
        return "login";
    }


    //...
}

```

다음으로, WebSecurityConfig class 에서 HttpSecurity 설정을 바꿔주자

```java

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //...

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http // HttpSecurity 객체를 설정한다.
                .authorizeRequests() // 권한요청 처리 설정 메서드이다.
                .antMatchers("/private/**").hasAnyRole("USER") // /private 이하의 모든 요청은 USER 역할이 있어야한다.
                .anyRequest().permitAll() // 다른 요청은 누구든지 접근 할 수 있다.
        .and()
            .formLogin()
            .loginPage("/login"); // 이곳이 추가 되었다.
    }

    //...
}
```

.formLogin() 의 .loginPage() 를 설정하게 되면, 시큐리티는 더 이상, 자신의 페이지를 보여주지 않고, 개발자가 설정 한 컨트롤러로 바인딩한다.

이제 다시 부팅 후, [http://127.0.0.1:8080/private](http://127.0.0.1:8080/private) 로 접근 하고, 로그인 해보자.

잘 나오는 걸 확인 할 수 있다.

이제 스타일 시트를 include 해보자.

src/main/resources/static 아래에 css/main.css 파일을 만들자 그리고 아래 내용을 붙혀넣자

_main.css_

```css
* {
  box-sizing: border-box;
}
html,
body {
  width: 100%;
  height: 100vh;
  background-color: #eeeeee;
}
fieldset {
  width: 400px;
  background-color: #ffffff;
}

input {
  padding: 8px;
  width: 100%;
  margin-bottom: 20px;
}

button {
  width: 100%;
}
```

그 다음 login.html 에 해당 css 파일을 링크하자.

_login.html_

```html
<head>
  ...
  <link rel="stylesheet" th:href="@{/css/main.css}" />
</head>
```

다음으로, WebSecurityConfig 클래스의 WebSecurity 를 설정하자.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //...

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css", "/js");
    }

    //...
}

```

이제 다시 부팅 후 로그인 페이지로 들어가 보면, 스타일이 적용 된 페이지를 볼 수 있다.

한번 설정을 뺀 후 접근하고, 뭐가 다른지 스스로 확인 해 보자.

# Step - 6 sql 로 사용자 관리하기

사실 지금은 jvm 메모리 안에, 사용자를 만들고 이를 코드로 관리했다. 하지만, 사용자를 이런식으로 관리하기는 무리가 있다.

그래서 우리는 앞서 설치한 h2 데이터베이스를 이용하여, 사용자를 관리 해 보겠다.

먼저 드라이버를 설정하기 위해서, application.properties 를 변경 해 주자.

```properties
spring.datasource.url=jdbc:h2:~/test
spring.datasource.username=sa
spring.datasource.password=
spring.datasource.driver-class-name=org.h2.Driver

spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

spring.jpa.generate-ddl=true
spring.jpa.database=h2
spring.jpa.show-sql=true
spring.jpa.hibernate.ddl-auto=create
spring.jpa.hibernate.use-new-id-generator-mappings=false
```

기존에 mysql 을 연결 한 것과 크게 다르지 않으니, 자세한 부분은 생략하겠다.

jpa 도 이번문서의 내용에서는 다루지 않겠다.

이제 security 가 우리가 설정 한 db 에서 유저를 찾을 수 있도록 서비스를 구현해야한다.

먼저 UserDetailsServiceImpl class 를 만들고 UserDetailsService 를 구현하자

```java
package ziponia.spring.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return null;
    }
}

```

이곳에서 최종적으로 security context 객체인, UserDetails 를 반환해야한다.

이제 database 에서 User 테이블을 만들 수 있도록 엔티티를 생성 해주자.

_UserEntity.java_

```java
package ziponia.spring.security;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "tbl_users")
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue
    private Integer idx;

    private String username;

    private String password;
}

```

다음 초기 유저 를 생성 해 주도록하자.

resources 밑에 import.sql 파일을 만들어 다음 스크립트를 붙혀넣자.

_import.sql_

```sql
insert into tbl_users (idx, username, password) values (1, 'user', '{bcrypt}$2a$10$Wyc.IrbO.bqraF58565Yde6J6heWdARvbDUKfaQYr9v/IoHcQ1RlK');
```

password 값은 1234 를 passwordEncoder 로 암호화 한 값이다.

이제 우리가 아까 생성했던 UserDetailsServiceImpl.java 가 이 데이터베이스에서 찾을 수 있도록 쿼리를 만들어주자.

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @PersistenceContext
    private EntityManager em; // JPA

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        List<UserEntity> findUsers = em
                .createQuery("select v from UserEntity v where v.username = :username", UserEntity.class)
                .setParameter("username", s)
                .getResultList();

        if (findUsers.size() == 0) {
            throw new UsernameNotFoundException("유저를 찾을 수 없습니다.");
        }

        UserEntity userEntity = findUsers.get(0);

        List<GrantedAuthority> authorities = new ArrayList<>();
        GrantedAuthority role = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(role);

        return new User(userEntity.getUsername(), userEntity.getPassword(), authorities);
    }
}


```

다음으로, WebSecurityConfig.java 파일에서 userDetailsServiceImpl 을 Bean 으로 등록 한 후 AuthenticationManagerBuilder 를 수정하자

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // ...

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*auth.inMemoryAuthentication()
                .withUser("user") // user 계정을 생성했다. 이부분에 로그인아이디가 된다.
                .password(passwordEncoder().encode("1234")) // passwordEncoder 로 등록 한 인코더로 1234 를 암호화한다.
                .roles("USER"); // 유저에게 USER 라는 역할을 제공한다.*/

        auth
                .userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
    }

    // ...

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }
}
```

이제 애플리케이션을 재부팅 후 로그인 버튼을 누르면, 콘솔에 쿼리가 올라오는것을 확인 할 수 있다.

ROLE*USER 의 이미가 혼란스러울 수 있다. InMemory 형태에서는 USER 라고 등록 해도 가능헀지만, Database 에서 찾을 때는, ROLE*\* prefix 가 붙어야 한다. 이것은 Security 내부적으로 '역할' 의 의미를 ROLE\_ prefix 를 줌으로써 Authorize(권한) 과 구분시킨 것으로 보인다. 만약 변경하고 싶다면,

[https://github.com/spring-projects/spring-security/issues/4134](https://github.com/spring-projects/spring-security/issues/4134) 를 참조해 보시라

개인적으로는 나중에 Authorize 와 구분짓기 위해서, 변경 할 것을 권장하지 않는다.

# Step - 7 조금 더 파보기

지금 로그인 폼에 보면,

```html
<input type="text" name="username" placeholder="아이디를 입력 해 주세요." />
<br />
<input type="password" name="password" placeholder="비밀번호를 입력 해 주세요." />
<br />
```

형식으로 name 이 지정이 되어있다.

이는, security 에 기본값으로 username, 과 password 로 parameter 가 설정 되어있기 때문이다.

내부적으로는 이 형식을 호출 하게 되면

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username={username}&password={password}
```

형식으로 전달한다.

이 파라미터를 변경하려면,

WebSecurityConfig.java 에 HttpSecurity 의 FormLoginConfigurer 에서 수정을 할 수 있다.

말은 복잡하게 했지만 결과적으로는,

_WebSecurityConfig.java_

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // ...

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http // HttpSecurity 객체를 설정한다.
                .authorizeRequests() // 권한요청 처리 설정 메서드이다.
                .antMatchers("/private/**").hasAnyRole("USER") // /private 이하의 모든 요청은 USER 역할이 있어야한다.
                .anyRequest().permitAll() // 다른 요청은 누구든지 접근 할 수 있다.
        .and()
            .formLogin()
            .loginPage("/login")
            .usernameParameter("username") // username parameter
            .passwordParameter("password");  // password parameter
    }

    // ...
}
```

이게 끝이다.

parameter 를 변경 하고 싶다면, username 값과 password 값을 변경 해 준 후, form 안에 input name 값도 맞춰주면 된다.

# Step - 8 기본내용 정리하기

Spring boot 는 Spring Security 가 classpath 에 있으면, 전역적으로 Security 를 등록한다.

나중에, 기회가 되면, 더 살펴보겠지만,

AuthenticationManager 라는 객체가 Security Context 에다 인증받은 Context 객체를 등록하는 역할을 맡고있다.

굳이 체감상 느끼는 워크플로우를 따지자면,

UserDetailsService 가 UserDetails 라는 Context 객체를 리턴 하여, 리턴 한 Context 객체를 AuthenticationManager 가 전달받아, Security 의 Context 로 등록한다.

UserDetailsServiceImpl 의 return 객체가 그것이다.

나중에 Security Context 객체를 가지고 오고 싶다면, Authentication 객체를 쓰레드에서 로드 해 와 사용 할 수 있다.

```java

// with controller
@GetMapping(value = "/private/context")
public String privateContextPage(
        @AuthenticationPrincipal Authentication authentication
) {
    System.out.println(authentication.getPrincipal());

    return "private";
}

// else...
SecurityContextHolder.getContext().getAuthentication(); // Authentication 을 반환
```

주의 할 점은 Security 는 Filter 레벨에서 관리 되므로, 최상위 Servlet 필터에서 가지고 올 수 없다.

```java
package ziponia.spring.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import java.io.IOException;

@Order(Ordered.HIGHEST_PRECEDENCE)
@Configuration
public class RootFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Auth =>>> ");
        System.out.println(authentication);
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}

```

위 class 를 만들어보라! authentication 은 Null 이 뜰 것이다. (직접 해보는게 최고다.)

Context 객체를 가지고 오려면, Security Filter 보다 뒤에 Filter 가 위치 해야하는데,

Security Filter 의 위치는 기본적으로 -100 이다.

따라서, 해당 필터는 -99 번 째부터 Filter 에서 Authentication 객체를 가지고 올 수 있다.

만약에 위에 코드를 돌리고 싶다면,

```java
package ziponia.spring.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.*;
import java.io.IOException;

@Order(-99) // 여기
@Configuration
public class RootFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Auth =>>> ");
        System.out.println(authentication);
        filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy() {

    }
}

```

@Order 가 -99 로 바뀌어야 한다. 한번, 101 과 99 를 바꾸어 가면서 로그를 확인 해 보시라!

_마침_

Security 에서 단순 한 부분만 설명(이라고 하고 주저리라고 부른다.) 하였다.

하지만, 이대로 서비스 하기엔 뭔가 많이 부족하다.

- 권한 없는 페이지는 어떻게 나타낼것인가?
- Security Exception 처리때 로깅은 어떻게 남길것인가?
- 권한을 세부적으로 어떻게 나눌것인가?

등등

이부분에 대해서는 나중에 기회가 되면 좀 더 자세하게 얘기 해 보도록 하겠다.

참고로 예제소스는

[https://github.com/ziponia/spring-security-example](https://github.com/ziponia/spring-security-example) 에서 확인 할 수 있다.

--- 

---
layout: post
title: "[SPRING] Spring Security 사용하기 #2"
---

Security 예외처리를 설정 해보자.

[지난 포스트](/2019/05/15/spring-security-with-boot/) 에서 시큐리티에 대한 기본설정을 해보았다.

이번엔, 좀 더 나아가 예외상황을 직접 커스터마이징 해보자.

# Access Denied (접근 거부) 핸들링

먼저 ROLE_ADMIN 권한 만 접근 할 수 있는 페이지와, 접근이 거부 되었을때 나오는 페이지를 만들어 주자.

_templates/admin.html_

```html
<!DOCTYPE html>
<html lang="ko">
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0"
    />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <title>Document</title>
  </head>
  <body>
    admin 만 들어 올 수 있는 페이지
  </body>
</html>
```

_templates/access-denied.html_

```html
<!DOCTYPE html>
<html lang="ko">
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0"
    />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <title>Document</title>
  </head>
  <body>
    접근이 거부되었습니다.
  </body>
</html>
```

그리고 admin 페이지는 /admin 으로, 접근 거부는 /access-denied 경로로 랜더링 할 수 있는 컨트롤러를 설정하자.

_SecurityController.java_

```java
@Controller
public class SecurityController {

    //...

    @GetMapping(value = "/admin")
    public String adminPage() {
        return "admin";
    }

    @GetMapping(value = "/access_denied")
    public String adminPage() {
        return "access_denied";
    }


    //...
}

```

이제 WebSecurityConfig 에서 다음과 같이 변경 해보자.

```java
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // ...

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/private/**").hasAnyRole("USER")
                .antMatchers("/admin/**").hasAnyRole("ADMIN") // admin 경로 추가
                .anyRequest().permitAll()
        .and()
            .formLogin()
            .loginPage("/login")
            .usernameParameter("username")
            .passwordParameter("password")
            .failureUrl("/login?error=true")
        .and()
            .logout()
            .deleteCookies("JSESSIONID")
            .clearAuthentication(true)
            .invalidateHttpSession(true)
        .and()
            .exceptionHandling()
                .accessDeniedPage("/access_denied")// access denied page
        ;
    }

    // ...
}

```

> GET /access-denied 는 Security 가 이미 Bean 으로 잡고있어서 못쓴다. 주의하자

이제 서버를 부팅 후, /admin 페이지로 들어가보자. 로그인 창이 뜨고, user / 1234 로 로그인 하게되면, user 는 ADMIN 권한을 가지고 있지 않기 때문에, 접근 거부 페이지가 뜰 것이다.

원활한 개발을 위해 간단하게 네비게이션 메뉴를 추가 해 보자. thymeleaf fragment 를 추가 할껀데, 보여주기만 할거니 자세하게는 몰라도 된다.

_pom.xml_

```xml
<dependency>
    <groupId>nz.net.ultraq.thymeleaf</groupId>
    <artifactId>thymeleaf-layout-dialect</artifactId>
    <version>2.4.1</version>
</dependency>
```

_templates/layout/layout.html_

```html
<!DOCTYPE html>
<html
  lang="ko"
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
>
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0"
    />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <link
      rel="stylesheet"
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css"
    />
    <link
      rel="stylesheet"
      href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap-theme.min.css"
    />
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
    <title>Document</title>
  </head>
  <body>
    <div class="container-fluid">
      <th:block th:replace="layout/navigation" />
      <th:block layout:fragment="contents" />
    </div>
  </body>
</html>
```

_templates/layout/navigation.html_

```html
<html xmlns:th="http://www.thymeleaf.org" xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout">
  <th:block layout:fragment="navigation">
    <nav class="navbar navbar-default">
      <ul class="nav navbar-nav">
        <li><a th:href="@{/}">홈</a></li>
        <li><a th:href="@{/admin}">관리자 페이지</a></li>
        <li><a th:href="@{/private}">개인 페이지</a></li>
        <li>
          <a href="javascript: void(0);" onclick="document.getElementById('logout-form').submit()">
            로그아웃
          </a>
        </li>
      </ul>
    </nav>
    <form id="logout-form" th:action="@{/logout}" method="post"></form>
  </th:block>
</html>
```

> 2019년 5월 16일 노트. security 의 logout 기본설정은 GET /logout 이 아니고 POST /logout 이다.

_access_denied.html_

```html
<html
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
  layout:decorator="layout/layout"
>
  <th:block layout:fragment="contents">
    <h1>접근이 거부되었습니다.</h1>
  </th:block>
</html>
```

_admin.html_

```html
<html
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
  layout:decorator="layout/layout"
>
  <th:block layout:fragment="contents">
    <h1>접근이 거부되었습니다.</h1>
  </th:block>
</html>
```

_index.html_

```html
<html
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
  layout:decorator="layout/layout"
>
  <th:block layout:fragment="contents">
    <h1>안녕하세요 시큐리티 홈 입니다..</h1>
  </th:block>
</html>
```

_private.html_

```html
<html
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
  layout:decorator="layout/layout"
>
  <th:block layout:fragment="contents">
    <h1>비공개 페이지</h1>
  </th:block>
</html>
```

_public.html_

```html
<html
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
  layout:decorator="layout/layout"
>
  <th:block layout:fragment="contents">
    <h1>public 페이지</h1>
  </th:block>
</html>
```

이제 ADMIN 유저를 추가 해보자. import.sql 에 추가하면 된다.

_import.sql_

```sql
insert into tbl_users (idx, username, password) values (1, 'user', '{bcrypt}$2a$10$Wyc.IrbO.bqraF58565Yde6J6heWdARvbDUKfaQYr9v/IoHcQ1RlK');
insert into tbl_users (idx, username, password) values (2, 'admin', '{bcrypt}$2a$10$Wyc.IrbO.bqraF58565Yde6J6heWdARvbDUKfaQYr9v/IoHcQ1RlK');
```

그리고 admin 유저가 ADMIN 역할을 소유 할 수 있도록 UserDetailsServiceImpl 에 설정 해주자.

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @PersistenceContext
    private EntityManager em; // JPA

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        // ...

        if (s.equals("admin")) {
            GrantedAuthority adminRole = new SimpleGrantedAuthority("ROLE_USER");
            authorities.add(adminRole);
        }

        return new User(userEntity.getUsername(), userEntity.getPassword(), authorities);
    }
}

```

이제 각각 user / 1234 와 admin / 1234 로 로그인 - 로그아웃을 반복하면서, admin 페이지에 접근 해 보면 admin 만 접근 할 수있는것을 확인 할 수 있을것이다.

이제 해당 페이지에 접근 하려고 하였을때, 로그를 기록하자

먼저 CustomAccessDeniedHandler class 를 만들고 AccessDeniedHandlerImpl 를 상속받아서 구현하자.

```java
package ziponia.spring.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Configuration
public class CustomAccessDeniedHandler extends AccessDeniedHandlerImpl {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        this.setErrorPage("/access_denied");
        log.info("Access Denied Request: {}, {}", request.getRemoteHost(), request.getRemoteUser());
        super.handle(request, response, accessDeniedException);
    }
}
```

그 다음 WebSecurityConfig 파일로 가서 HttpSecurity 를 교체 해 주면 된다.

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/private/**").hasAnyRole("USER")
                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                .anyRequest().permitAll()
        .and()
            .formLogin()
            .loginPage("/login")
            .usernameParameter("username")
            .passwordParameter("password")
            .failureUrl("/login?error=true")
        .and()
            .exceptionHandling()
                // .accessDeniedPage("/access_denied")
                .accessDeniedHandler(customAccessDeniedHandler)

        ;
    }
}

```

이제 user 로 로그인 해서 관리자 페이지에 들어가면, 위 로그가 뜨는 것을 확인 할 수 있다.

---

---
layout: post
title: "[SPRING] Spring Security 사용하기 #3"
---

social login 서비스를 구현해보자

이번에는 좀 재미있는것을 해보자.

카카오로그인, 페이스북 로그인 같은 소셜 로그인을 구현 할것이다.

# facebook 로그인 / github 로그인

사전작업으로 https://developers.facebook.com/ 에 가서 새로운 앱을 만든 후, client id 와 client secret 를 받아두자.

로그인을 할것이니, 로그인 설정을 하는것도 잊지말자.

먼저 의존성을 다운받자

_pom.xml_

```xml
<dependency>
    <groupId>org.springframework.security.oauth.boot</groupId>
    <artifactId>spring-security-oauth2-autoconfigure</artifactId>
    <version>2.1.4.RELEASE</version>
</dependency>
```

그 다음 Application 전역에 @EnableOAuth2Sso 어노테이션을 달아주자.

다음으로 application.yml 파일을 resources 아래 만들어서 다음과 같은 내용을 넣어주자

```
facebook:
  client:
    clientId: {my client id}
    clientSecret: {my client secret}
    accessTokenUri: https://graph.facebook.com/oauth/access_token
    userAuthorizationUri: https://www.facebook.com/dialog/oauth
    tokenName: oauth_token
    authenticationScheme: query
    clientAuthenticationScheme: form
  resource:
    userInfoUri: https://graph.facebook.com/me
```

my client id 와 my client secret 항목에서 facebook 에서 발급받은 client id 와 client secret 를 넣어주면 된다.

그리고 WebSecurityConfig 를 다음과 같이 수정한다.

```java
@Configuration
@EnableWebSecurity
@EnableOAuth2Client // new
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //...

    @Autowired
    private OAuth2ClientContext auth2ClientContext;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/private/**").hasAnyRole("USER")
                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                .anyRequest().permitAll()
        .and()
            .formLogin()
            .loginPage("/login")
            .usernameParameter("username")
            .passwordParameter("password")
            .failureUrl("/login?error=true")
        .and()
            .logout()
            .deleteCookies("JSESSIONID")
            .clearAuthentication(true)
            .invalidateHttpSession(true)
        .and()
            .exceptionHandling()
                // .accessDeniedPage("/access_denied")
                .accessDeniedHandler(customAccessDeniedHandler)
        .and() // new
            .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class) // new
        ;
    }

    // new
    private Filter ssoFilter() {
        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
        OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), auth2ClientContext);
        facebookFilter.setRestTemplate(facebookTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId());
        tokenServices.setRestTemplate(facebookTemplate);
        facebookFilter.setTokenServices(tokenServices);
        return facebookFilter;
    }

    // new
    @Bean
    @ConfigurationProperties("facebook.client")
    public AuthorizationCodeResourceDetails facebook() {
        return new AuthorizationCodeResourceDetails();
    }

    // new
    @Bean
    @ConfigurationProperties("facebook.resource")
    public ResourceServerProperties facebookResource() {
        return new ResourceServerProperties();
    }

    // new
    @Bean
    public OAuth2ClientContext auth2ClientContext() {
        return new DefaultOAuth2ClientContext();
    }

    // new
    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }
}
```

new 라고 주석처리 한 항목을 수정 하면 된다.

이제 login.html 에 다음과 같이 넣어주겠다.

_login.html_

```html
<fieldset>
  <legend>로그인</legend>
  <form th:action="@{/login}" th:method="post">
    <input type="text" name="username" placeholder="아이디를 입력 해 주세요." />
    <br />
    <input type="password" name="password" placeholder="비밀번호를 입력 해 주세요." />
    <br />
    <button type="submit">로그인</button>
  </form>
  <div>
    <a th:href="@{/login/facebook}">페이스북 로그인</a>
    <!-- 이부분을 추가하자. -->
  </div>
</fieldset>
```

그리고 현재 유저 정보를 볼 수 있도록, /private 에 현재 유저 id 를 가지고 올 수 있도록 하자

_SecurityController.java_

```java
@Controller
public class SecurityController {

    @GetMapping(value = "/private")
    public String privatePage(Principal principal, Model model) {
        model.addAttribute("user", principal);
        return "private";
    }
}
```

_private.html_

```html
<html
  xmlns:th="http://www.thymeleaf.org"
  xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
  layout:decorator="layout/layout"
>
  <th:block layout:fragment="contents">
    <h1>비공개 페이지</h1>
    <p th:text="${user.name}"></p>
  </th:block>
</html>
```

그럼 비공개 페이지 밑에 자기 자신의 아이디가 뜨는 것을 알 수 있다.

# Github 로그인

이제 깃헙 로그인을 추가 해보자. 당연히 이번에도 github 에서 oauth2 어플리케이션을 추가해야한다.

_login.html_

```html
<fieldset>
  <legend>로그인</legend>
  <form th:action="@{/login}" th:method="post">
    <input type="text" name="username" placeholder="아이디를 입력 해 주세요." />
    <br />
    <input type="password" name="password" placeholder="비밀번호를 입력 해 주세요." />
    <br />
    <button type="submit">로그인</button>
  </form>
  <div>
    <a th:href="@{/login/facebook}">페이스북 로그인</a>
  </div>
  <div>
    <a th:href="@{/login/github}">깃허브 로그인</a>
  </div>
</fieldset>
```

_application.yml_

```
github:
  client:
    clientId: {my client id}
    clientSecret: {my client secret}
    accessTokenUri: https://github.com/login/oauth/access_token
    userAuthorizationUri: https://github.com/login/oauth/authorize
    clientAuthenticationScheme: form
  resource:
    userInfoUri: https://api.github.com/user
```

_WebSecurityConfig.java_

```java
@Configuration
@EnableWebSecurity
@EnableOAuth2Client
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // ...
    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();

        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
        OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), auth2ClientContext);
        facebookFilter.setRestTemplate(facebookTemplate);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId());
        tokenServices.setRestTemplate(facebookTemplate);
        facebookFilter.setTokenServices(tokenServices);
        filters.add(facebookFilter);

        OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
        OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), auth2ClientContext);
        githubFilter.setRestTemplate(githubTemplate);
        tokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId());
        tokenServices.setRestTemplate(githubTemplate);
        githubFilter.setTokenServices(tokenServices);
        filters.add(githubFilter);

        filter.setFilters(filters);
        return filter;
    }

    @Bean
    @ConfigurationProperties("github.client")
    public AuthorizationCodeResourceDetails github() {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("github.resource")
    public ResourceServerProperties githubResource() {
        return new ResourceServerProperties();
    }

    //...
}

```

ssoFilter 쪽만 변경 하면 된다.

이전에 facebook 로그인을 구현해놔서 복잡하진 않을것이다.

facebook 과 github 쪽에 filter 가 비슷하게 생겼다. 메뉴얼에 따라 리펙토링을 해보자.

먼저 ClientResources 를 만든다.

```java
class ClientResources {

    @NestedConfigurationProperty
    private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }
}
```

다음으로, WebSecurityConfig 쪽을 수정하자

_WebsecurityConfig.java_

```java
@Configuration
@EnableWebSecurity
@EnableOAuth2Client
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilter(github(), "/login/github"));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), auth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        filter.setTokenServices(tokenServices);
        return filter;
    }

    @Bean
    @ConfigurationProperties("github")
    public ClientResources github() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("facebook")
    public ClientResources facebook() {
        return new ClientResources();
    }
}

```

이 예제는 [https://spring.io/guides/tutorials/spring-boot-oauth2/#\_social_login_github](https://spring.io/guides/tutorials/spring-boot-oauth2/#_social_login_github) 예제 이다.

이제 페이스북 로그인 / 깃허브 로그인을 번갈아가며 해보자.

# 카카오 로그인 추가하기

예제만 따라해서는 의미가 없다. 응용해서 카카오 로그인을 구현해보자.

[카카오 개발자센터](https://developers.kakao.com/) 에서 키 발급받는거 있지 말자

이제 차근차근 응용해보자.

먼저 WebSecurityConfig 를 바꿔보자

```java
@Configuration
@EnableWebSecurity
@EnableOAuth2Client
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook"));
        filters.add(ssoFilter(github(), "/login/github"));
        filters.add(ssoFilter(kakao(), "/login/kakao")); // new
        filter.setFilters(filters);
        return filter;
    }

    // new
    @Bean
    @ConfigurationProperties("kakao")
    public ClientResources kakao() {
        return new ClientResources();
    }
}
```

다음으로 application.yml 에 카카오 정보를 입력 해 보자.

```
kakao:
  client:
    clientId: {kakao rest api key}
    clientSecret: {kakao secret key}
    accessTokenUri: https://kauth.kakao.com/oauth/token
    userAuthorizationUri: https://kauth.kakao.com/oauth/authorize
    clientAuthenticationScheme: form
  resource:
    userInfoUri: https://kapi.kakao.com/v2/user/me
```

각프로퍼티들은 문서에 있는 내용들이다.

이제 로그인 페이지에 카카오 로그인을 추가하자

_login.html_

```html
<fieldset>
  <legend>로그인</legend>
  <form th:action="@{/login}" th:method="post">
    <input type="text" name="username" placeholder="아이디를 입력 해 주세요." />
    <br />
    <input type="password" name="password" placeholder="비밀번호를 입력 해 주세요." />
    <br />
    <button type="submit">로그인</button>
  </form>
  <div>
    <a th:href="@{/login/facebook}">페이스북 로그인</a>
  </div>
  <div>
    <a th:href="@{/login/github}">깃허브 로그인</a>
  </div>
  <div>
    <a th:href="@{/login/kakao}">카카오 로그인</a>
  </div>
</fieldset>
```

너무 쉽게 끝났다. security 는 정말 놀랍지 않은가. 오늘은 여기까지

현재까지의 소스는 [https://github.com/ziponia/spring-security-example](https://github.com/ziponia/spring-security-example) tag v2 로 따라가자


---
layout: post
title: "[SPRING] Spring Security 사용하기 #4"
---

Spring boot oauth2 에 Database 를 연결 하자

이번에는 지난 시간에 한 oauth2 로그인에 이어, Database 와 연동을 해보겠다.

이번에 구현 할 것은, 1 계정 - 1소셜 이다

무슨 말이냐 하면, 유저 1 : N 소셜 이 아니라, 소셜 계정이 즉 유저계정이 된다는 것이다.

따라서, User 가 소셜 일 수도있고, 아닐수도 있다는 이야기이다.

먼저, 소셜 타입을 정의하자.

```java
package ziponia.spring.security;

public enum SocialProvider {
    KAKAO,
    FACEBOOK,
    GITHUB
}

```

다음으로 User 테이블에 SocialProvider 를 추가하자

```java
package ziponia.spring.security;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name = "tbl_users")
@Getter
@Setter
public class UserEntity {

    @Id
    @GeneratedValue
    private Integer idx;

    private String username;

    private String password;

    @Enumerated(EnumType.STRING)
    private SocialProvider sns; // new
}

```

다음으로, 권한 및 인증 추출기를 만들겠다.

프로젝트가 조금 복잡해지니, social 이라는 패키지를 만들고 그 안에 facebook / github / kakao 라는 패키지를 만든다. 그 다음 social 패키지 아래에 BasePrincipalExtractor 라는 추상화 객체를 만들겠다.

쿼리를 중복해서 써야 하는 부분을 제거하기 위함이다.

그럼 최종적으로

BasePrincipalExtractor 라는 추상화 객체가 있고, BasePrincipalExtractor 는 PrincipalExtractor 를 구현한 후

FacebookAuthoritiesExtractor, GithubAuthoritiesExtractor, KakaoPrincipalExtractor 클래스들이 BasePrincipalExtractor 를 상속하는 것이다.

```java
@Component
public abstract class BasePrincipalExtractor implements PrincipalExtractor {
}

```

```java
@Component
public class FacebookPrincipalExtractor extends BasePrincipalExtractor {

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        return null;
    }
}

```

```java
@Component
public class KakaoPrincipalExtractor extends BasePrincipalExtractor {

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        return null;
    }
}

```

```java
@Component
public class GithubPrincipalExtractor extends BasePrincipalExtractor {

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        return null;
    }
}

```

그리고, Database 로 접근 할 수 있는, JpaRepository를 하나 만들자.

> 다시한번 얘기하지만, JPA 는 지금 언급하지 않겠다.

_UserRepository.java_

```java
public interface UserRepository extends JpaRepository<UserEntity, Integer> {
}
```

이제 BasePrincipalExtractor 에서 UserRepository 를 주입시켜준 후, Social 계정을 받아 처리 할 수 있는, 쿼리를 만들고,

최종적으로 Principal 을 대신해서 생성 해 주는 부분 까지 생성하자.

```java
public abstract class BasePrincipalExtractor implements PrincipalExtractor {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String[] PRINCIPAL_KEYS = new String[] { "user", "username",
            "userid", "user_id", "login", "id", "name" };

    @Transactional
    public void saveSocialUser(String id, SocialProvider provider) {
        UserEntity userEntity = userRepository.findByUsernameAndSns(id, provider);
        if (userEntity == null) {
            userEntity = new UserEntity();
            userEntity.setUsername(id);
            userEntity.setSns(provider);
            userEntity.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
        }

        userRepository.save(userEntity);
    }

    protected Object createPrincipal(Map<String, Object> map) {
        for (String key : PRINCIPAL_KEYS) {
            if (map.containsKey(key)) {
                return map.get(key);
            }
        }
        return null;
    }
}
```

이제 각각, Facebook, github, kakao PrincipalExtractor 에서 saveSocialUser 메서드를 불러와 사용하자.

반복코드니, 카카오 예시 하나만 보겠다.

```java
@Component
public class KakaoPrincipalExtractor extends BasePrincipalExtractor {

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        String id = map.get("id").toString();
        this.saveSocialUser(id, SocialProvider.KAKAO); // 이부분만 각각 맞는걸로 교체 해 주면 된다.
        return this.createPrincipal(map);
    }
}
```

마지막으로, WebSecurityConfig 를 살짝 건드려 주면 된다.

_WebSecurityConfig.java_

```java
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private FacebookPrincipalExtractor facebookPrincipalExtractor;

    @Autowired
    private KakaoPrincipalExtractor kakaoPrincipalExtractor;

    @Autowired
    private GithubPrincipalExtractor githubPrincipalExtractor;

    // ...
    private Filter ssoFilter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(ssoFilter(facebook(), "/login/facebook", SocialProvider.FACEBOOK));
        filters.add(ssoFilter(github(), "/login/github", SocialProvider.GITHUB));
        filters.add(ssoFilter(kakao(), "/login/kakao", SocialProvider.KAKAO));
        filter.setFilters(filters);
        return filter;
    }

    private Filter ssoFilter(ClientResources client, String path, SocialProvider provider) {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), auth2ClientContext);
        filter.setRestTemplate(template);
        UserInfoTokenServices tokenServices = new UserInfoTokenServices(
                client.getResource().getUserInfoUri(), client.getClient().getClientId());
        tokenServices.setRestTemplate(template);
        if (provider.equals(SocialProvider.FACEBOOK)) {
            tokenServices.setPrincipalExtractor(facebookPrincipalExtractor);
        }

        if (provider.equals(SocialProvider.GITHUB)) {
            tokenServices.setPrincipalExtractor(githubPrincipalExtractor);
        }

        if (provider.equals(SocialProvider.KAKAO)) {
            tokenServices.setPrincipalExtractor(kakaoPrincipalExtractor);
        }
        filter.setTokenServices(tokenServices);
        return filter;
    }

    // ...
}
```

이제 각각 로그인을 하면서, 확인 해 보면 새로운 레코드가 추가 되는걸 볼 수 있다.

_최초_

![최초이미지](/images/2019-5-17/security_oauth_default_record.png)

_페이스북 로그인 후_

![페이스북추가](/images/2019-5-17/security_oauth_default_facebook.png)

_깃허브 로그인 후_

![깃허브추가](/images/2019-5-17/security_oauth_default_github.png)

카카오 로그인은 직접 해보자

소스는

[https://github.com/ziponia/spring-security-example](https://github.com/ziponia/spring-security-example)

tag v3 로 가자
