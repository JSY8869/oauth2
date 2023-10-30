package oauth.kakao.security.token.creator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import oauth.kakao.security.auth.UserPrincipal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static oauth.kakao.security.token.common.TokenProperties.*;

@Component
public class JwtTokenCreator {


    @Value("${JWT_SECRET_KEY}")
    private String JWT_SECRET_KEY;
    @Value("${JWT_REFRESH_SECRET_KEY}")
    private String JWT_REFRESH_SECRET_KEY;

    public String createAccessToken(UserPrincipal userPrincipal) {
        Date now = new Date();
        Claims claims = setClaims(userPrincipal);
        return ACCESS_TOKEN_PREFIX + Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + ACCESS_TOKEN_EXPIRED_TIME))
                .signWith(new SecretKeySpec(JWT_SECRET_KEY
                        .trim().getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName()))
                .compact();
    }

    public String createRefreshToken(UserPrincipal userPrincipal) {
        Date now = new Date();
        Claims claims = setClaims(userPrincipal);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + REFRESH_TOKEN_EXPIRED_TIME))
                .signWith(new SecretKeySpec(JWT_REFRESH_SECRET_KEY
                        .trim().getBytes(StandardCharsets.UTF_8), SignatureAlgorithm.HS256.getJcaName()))
                .compact();
    }

    private Claims setClaims(UserPrincipal userPrincipal) {
        Claims claims = Jwts.claims();
        claims.put("email", userPrincipal.getUsername());
        claims.put("role", userPrincipal.getRoleType().name());
        claims.setSubject(String.valueOf(userPrincipal.getId()));
        return claims;
    }
}
