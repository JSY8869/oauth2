package oauth.kakao.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import oauth.kakao.security.auth.JwtAuthenticationToken;
import oauth.kakao.security.auth.UserPrincipal;
import oauth.kakao.security.token.domain.JwtAccessToken;
import oauth.kakao.security.token.extractor.JwtTokenExtractor;
import oauth.kakao.security.token.provider.JwtTokenProvider;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final JwtTokenProvider tokenProvider;
    private final JwtTokenExtractor tokenExtractor;


    private static final String ACCESSTOKEN_HEADER = "AccessToken";
    private static final String REFRESHTOKEN_HEADER = "RefreshToken";
    private static final String[] ANONYMOUS_END_POINT = {"/", "/health-check", "/login", "/register", "/auth/token", "/oauth2/authorization/kakao"};

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  JwtTokenProvider tokenProvider,
                                  JwtTokenExtractor jwtTokenExtractor) {
        super(authenticationManager);
        this.tokenProvider = tokenProvider;
        this.tokenExtractor = jwtTokenExtractor;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException{
        // Header 검증
        String accessToken = request.getHeader(ACCESSTOKEN_HEADER);
        if(accessToken == null) {
            if (isAnonymousRequest(request)) {
                // 액세스 토큰이 없다면 다음 필터에서 익명 사용자로 처리
                filterChain.doFilter(request, response);
                return;
            } else {
                throw new AccessDeniedException("인증 access 헤더가 존재하지 않습니다");
            }
        }

        UserPrincipal userPrincipal;
        try {
            // 헤더 값으로 access token 검증
            userPrincipal = tokenExtractor.extractAccessToken(accessToken);

            // access token이 검증되었다면 인증 객체를 생성 후 시큐리티 컨텍스트에 인증 객체 저장
            setAuthentication(userPrincipal);

        } catch(ExpiredJwtException e1) {
            String refreshToken = request.getHeader(REFRESHTOKEN_HEADER);

            if (refreshToken == null) {
                if (isAnonymousRequest(request)) {
                    // 액세스 토큰이 없다면 다음 필터에서 익명 사용자로 처리
                    filterChain.doFilter(request, response);
                    return;
                }
                else {
                    throw new AccessDeniedException("인증 refresh 헤더가 존재하지 않습니다");
                }
            }

            try {
                userPrincipal = tokenExtractor.extractRefreshToken(refreshToken);

                // 검증이 완료되었다면 access token 재발급 후 헤더에 담는다
                JwtAccessToken reIssuedAccessToken = tokenProvider.issueAccessToken(userPrincipal);
                response.setHeader(ACCESSTOKEN_HEADER, reIssuedAccessToken.getValue());

                // refresh token이 검증되었다면 인증 객체를 생성
                setAuthentication(userPrincipal);

            } catch(ExpiredJwtException e2) {
                // 리프레쉬 토큰도 만료가 되었다면 시큐리티 컨텍스트를 비우고
                SecurityContextHolder.clearContext();

                // 그냥 예외를 던진다
                throw new ExpiredJwtException(e2.getHeader(), e2.getClaims(), e2.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }

    private static void setAuthentication(UserPrincipal userPrincipal) {
        Authentication authentication = JwtAuthenticationToken
                .authenticated(userPrincipal, null, userPrincipal.getAuthorities());

        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }
    private static boolean isAnonymousRequest(HttpServletRequest request) {
        return Arrays.stream(ANONYMOUS_END_POINT).anyMatch(path -> path.equals(request.getRequestURI()));
    }
}
