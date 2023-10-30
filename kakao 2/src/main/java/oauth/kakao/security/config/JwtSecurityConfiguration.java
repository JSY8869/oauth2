package oauth.kakao.security.config;

import lombok.RequiredArgsConstructor;
import oauth.kakao.security.service.CustomOAuth2UserService;
import oauth.kakao.security.HttpCookieOAuth2AuthorizationRequestRepository;
import oauth.kakao.security.RestAuthenticationEntryPoint;
import oauth.kakao.security.filter.JwtAuthorizationExceptionFilter;
import oauth.kakao.security.filter.JwtAuthorizationFilter;
import oauth.kakao.security.handler.failure.CustomAccessDeniedHandler;
import oauth.kakao.security.handler.failure.OAuthAuthenticationFailureHandler;
import oauth.kakao.security.handler.logout.JwtLogoutHandler;
import oauth.kakao.security.handler.logout.JwtLogoutSuccessHandler;
import oauth.kakao.security.handler.success.OAuthAuthenticationSuccessHandler;
import oauth.kakao.security.token.extractor.JwtTokenExtractor;
import oauth.kakao.security.token.provider.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class JwtSecurityConfiguration {

    private static final String LOGOUT_END_POINT = "/user/sign-out";
    private static final String[] PUBLIC_END_POINT = {"/"};
    private static final String[] ANONYMOUS_END_POINT = {"/", "/health-check", "/login"};

    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final OAuthAuthenticationSuccessHandler oAuthAuthenticationSuccessHandler;
    private final OAuthAuthenticationFailureHandler oAuthAuthenticationFailureHandler;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtTokenExtractor jwtTokenExtractor;
    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieOAuth2AuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        /*
         * REST API 서버를 기반으로 하기 때문에 CSRF 필터 해제, 폼 로그인 사용 X
         * JWT 토큰 기반의 인증, 인가를 위해 HTTP Basic 인증 사용 X, 세션 생성 및 사용 X
         */
        http.cors()
            .and()
            .csrf().disable()
            .formLogin().disable()
            .httpBasic().disable()
            .headers().frameOptions().disable()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션을 사용하지 않음

        // 로그아웃 설정
        http.logout()
                .logoutUrl(LOGOUT_END_POINT)
                .addLogoutHandler(new JwtLogoutHandler())
                .logoutSuccessHandler(new JwtLogoutSuccessHandler());

        // 인가 API
        http.authorizeRequests()
                .antMatchers("/auth/**", "/oauth2/**").permitAll()
                .antMatchers(PUBLIC_END_POINT).permitAll()
                .antMatchers(ANONYMOUS_END_POINT).anonymous()
                .anyRequest().authenticated();

        // oauth 설정
        http
            .oauth2Login()
                .authorizationEndpoint().baseUri("/oauth2/authorization") // 소셜 로그인 Url
                .authorizationRequestRepository(cookieOAuth2AuthorizationRequestRepository()) // 인증 요청을 쿠키에 저장하고 검색
                .and()
                .redirectionEndpoint().baseUri("/oauth2/callback/*") // 소셜 인증 후 Redirect Url
                .and()
                .userInfoEndpoint().userService(customOAuth2UserService) // 소셜의 회원 정보를 받아와 가공처리
                .and()
                .successHandler(oAuthAuthenticationSuccessHandler) // 인증 성공 시 Handler
                .failureHandler(oAuthAuthenticationFailureHandler); // 인증 실패 시 Handler

        http.exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())// 인증,인가가 되지 않은 요청 시 발생
                .accessDeniedHandler(customAccessDeniedHandler);

        // JWT DSL 추가
        http.apply(new JwtCustomDsl());

        return http.build();
    }

    // 공유객체에서 Authentication Manager 를 가져와 사용하기 위해 CustomDSL 정의
    public class JwtCustomDsl extends AbstractHttpConfigurer<JwtCustomDsl, HttpSecurity> {

        @Override
        public void configure(HttpSecurity http) {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            JwtAuthorizationFilter jwtMemoryAuthorizationFilter =
                    new JwtAuthorizationFilter(authenticationManager, jwtTokenProvider, jwtTokenExtractor);
            JwtAuthorizationExceptionFilter jwtAuthorizationExceptionFilter = new JwtAuthorizationExceptionFilter();
            http.addFilterBefore(jwtMemoryAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
            http.addFilterBefore(jwtAuthorizationExceptionFilter, JwtAuthorizationFilter.class);
        }
    }
}
