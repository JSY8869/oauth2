package oauth.kakao.security.token.domain;

import java.util.Date;

import static oauth.kakao.security.token.common.TokenProperties.ACCESS_TOKEN_EXPIRED_TIME;

public class JwtAccessToken {

    private final Date expiredAt;
    private final String value;
    Date createdAt = new Date();

    public JwtAccessToken(String value) {
        this.expiredAt = getDefaultExpiredAt();
        this.value = value;
    }

    private Date getDefaultExpiredAt() {
        return new Date(this.createdAt.getTime() + ACCESS_TOKEN_EXPIRED_TIME);
    }

    public String getValue() {
        return value;
    }

}
