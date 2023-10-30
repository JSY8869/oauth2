package oauth.kakao.dto.common;

import org.springframework.lang.Nullable;

public record SuccessResponseBody(
        String code,
        String message,
        @Nullable Object data
) {
}
