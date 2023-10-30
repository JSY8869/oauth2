package oauth.kakao.security.token.decoder;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static oauth.kakao.security.token.common.TokenProperties.ACCESS_TOKEN_PREFIX;

@Component
public class JwtTokenDecoder {

    @Value("${JWT_SECRET_KEY}")
    private String JWT_SECRET_KEY;
    @Value("${JWT_REFRESH_SECRET_KEY}")
    private String JWT_REFRESH_SECRET_KEY;

    public Claims decodeAccessToken(String accessToken) {
        try {
            // Token prefix 와 실제 토큰 값을 분리
            String rawAccessToken = accessToken.split(ACCESS_TOKEN_PREFIX)[1];
            Claims claims = getClaimsByJwtToken(rawAccessToken, JWT_SECRET_KEY);
            return claims;
        } catch (UnsupportedJwtException | ArrayIndexOutOfBoundsException e) {
            throw new UnsupportedJwtException("지원하지 않는 토큰입니다.");
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("조작된 토큰입니다.");
        } catch (io.jsonwebtoken.security.SignatureException e) {
            throw new SignatureException("토큰 서명 확인에 실패 하였습니다.");
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException(e.getHeader(), e.getClaims(), "만료된 토큰입니다.");
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("토큰의 값이 존재하지 않습니다.");
        }
    }

    public Claims decodeRefreshToken(String refreshToken) {
        try {
            Claims claims = getClaimsByJwtToken(refreshToken, JWT_REFRESH_SECRET_KEY);
            return claims;
        } catch (UnsupportedJwtException | ArrayIndexOutOfBoundsException e) {
            throw new UnsupportedJwtException("지원하지 않는 토큰입니다.");
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("조작된 토큰입니다.");
        } catch (io.jsonwebtoken.security.SignatureException e) {
            throw new SignatureException("토큰 서명 확인에 실패 하였습니다.");
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtException(e.getHeader(), e.getClaims(), "만료된 토큰입니다.");
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("토큰의 값이 존재하지 않습니다.");
        }
    }

    private Claims getClaimsByJwtToken(String jwtToken, String secretKey) {
        return Jwts.parserBuilder()
                .setSigningKey(new SecretKeySpec(secretKey
                        .trim().getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName()))
                .build().parseClaimsJws(jwtToken).getBody();
    }
}
