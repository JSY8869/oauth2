package oauth.kakao.security.handler.logout;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import oauth.kakao.dto.common.SuccessResponseBody;
import oauth.kakao.util.DefaultHttpMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class JwtLogoutSuccessHandler implements LogoutSuccessHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final static String LOGOUT_REDIRECT_END_POINT = "/login";

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {

        response.setStatus(HttpStatus.MOVED_PERMANENTLY.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.toString());

        objectMapper.writeValue(response.getWriter(), new SuccessResponseBody(
                String.valueOf(HttpStatus.MOVED_PERMANENTLY.value()),
                String.format(DefaultHttpMessage.MOVED_PERMANENTLY, LOGOUT_REDIRECT_END_POINT),
                null));
    }
}
