package oauth.kakao.security.token.common;

import java.time.Duration;

public interface TokenProperties {

    String ACCESS_TOKEN_PREFIX = "Bearer ";

    Long ACCESS_TOKEN_EXPIRED_TIME = Duration.ofSeconds(10).toMillis();
    Long REFRESH_TOKEN_EXPIRED_TIME = Duration.ofSeconds(14).toMillis();

}
