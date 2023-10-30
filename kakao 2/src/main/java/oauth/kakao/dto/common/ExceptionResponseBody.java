package oauth.kakao.dto.common;

import org.springframework.lang.Nullable;

public record ExceptionResponseBody(
        String code,
        Object message,
        @Nullable String detail
) {
}
