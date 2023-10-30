package oauth.kakao.security.token.provider;

import lombok.RequiredArgsConstructor;
import oauth.kakao.security.auth.UserPrincipal;
import oauth.kakao.security.token.creator.JwtTokenCreator;
import oauth.kakao.security.token.domain.JwtAccessToken;
import oauth.kakao.security.token.domain.JwtRefreshToken;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class JwtTokenProvider {

    private final JwtTokenCreator jwtTokenCreator;

    public JwtAccessToken issueAccessToken(UserPrincipal userPrincipal) {
        String accessToken = jwtTokenCreator.createAccessToken(userPrincipal);
        return new JwtAccessToken(accessToken);
    }

    public JwtRefreshToken issueRefreshToken(UserPrincipal userPrincipal) {
        String refreshToken = jwtTokenCreator.createRefreshToken(userPrincipal);
        return new JwtRefreshToken(refreshToken);
    }
}
