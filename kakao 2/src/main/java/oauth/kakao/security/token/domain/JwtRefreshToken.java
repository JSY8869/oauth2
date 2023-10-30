package oauth.kakao.security.token.domain;

import java.util.Date;

import static oauth.kakao.security.token.common.TokenProperties.REFRESH_TOKEN_EXPIRED_TIME;

public class JwtRefreshToken {

    private final Date expiredAt;
    private final String value;
    Date createdAt = new Date();

    public JwtRefreshToken(String value) {
        this.expiredAt = getDefaultExpiredAt();
        this.value = value;
    }

    private Date getDefaultExpiredAt() {
        return new Date(this.createdAt.getTime() + REFRESH_TOKEN_EXPIRED_TIME);
    }

    public String getValue() {
        return value;
    }

}
