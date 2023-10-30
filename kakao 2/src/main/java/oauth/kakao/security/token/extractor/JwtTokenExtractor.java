package oauth.kakao.security.token.extractor;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauth.kakao.security.auth.UserPrincipal;
import oauth.kakao.security.service.CustomUserDetailsService;
import oauth.kakao.security.token.decoder.JwtTokenDecoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtTokenExtractor {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtTokenDecoder jwtTokenDecoder;

    public UserPrincipal extractAccessToken(String accessToken) {
        Claims claims = jwtTokenDecoder.decodeAccessToken(accessToken);
        return toJwtUserDetails(claims);
    }

    public UserPrincipal extractRefreshToken(String refreshToken) {
        Claims claims = jwtTokenDecoder.decodeRefreshToken(refreshToken);
        return toJwtUserDetails(claims);
    }

    private UserPrincipal toJwtUserDetails(Claims claims) {
        UserPrincipal user = (UserPrincipal) customUserDetailsService.
                loadUserByUsername(claims.get("email", String.class));

        verify(claims, user);

        return user;
    }

    private void verify(Claims claims, UserPrincipal user) {
        if (!String.valueOf(user.getUser().getId()).equals(claims.getSubject())
                || !user.getUser().getRoleType().toString().equals(claims.get("role", String.class))) {
            throw new MalformedJwtException("변조된 토큰입니다.");
        }
    }
}
